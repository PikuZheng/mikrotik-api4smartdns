#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(improper_ctypes)]

pub mod smartdns_c {
    include!(concat!(env!("OUT_DIR"), "/smartdns_bindings.rs"));
}

use std::ffi::CStr;
use std::ffi::CString;
use std::net::{Ipv4Addr, Ipv6Addr};

// DNS type constants (from dns.h)
pub const DNS_T_A: i32 = 1;
pub const DNS_T_AAAA: i32 = 28;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum LogLevel {
    DEBUG = 0,
    INFO = 1,
    NOTICE = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5,
    OFF = 6,
}

impl TryFrom<u32> for LogLevel {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LogLevel::DEBUG),
            1 => Ok(LogLevel::INFO),
            2 => Ok(LogLevel::NOTICE),
            3 => Ok(LogLevel::WARN),
            4 => Ok(LogLevel::ERROR),
            5 => Ok(LogLevel::FATAL),
            6 => Ok(LogLevel::OFF),
            _ => Err(()),
        }
    }
}

#[macro_export]
macro_rules! dns_log {
    ($level:expr, $($arg:tt)*) => {
        if $crate::smartdns::dns_can_log($level) {
            $crate::smartdns::dns_log_out($level, file!(), line!(), &format!($($arg)*));
        }
    };
}

pub fn dns_can_log(level: LogLevel) -> bool {
    unsafe { smartdns_c::smartdns_plugin_can_log(level as u32) != 0 }
}

pub fn dns_log_out(level: LogLevel, file: &str, line: u32, message: &str) {
    let filename_only = std::path::Path::new(file)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap();
    let file_cstring = CString::new(filename_only).expect("Failed to convert to CString");
    let message_cstring = CString::new(message).expect("Failed to convert to CString");

    unsafe {
        smartdns_c::smartdns_plugin_log(
            level as u32,
            file_cstring.as_ptr(),
            line as i32,
            std::ptr::null(),
            message_cstring.as_ptr(),
        );
    }
}

/// Result from looking up the DNS cache for a completed query.
#[derive(Debug, Clone)]
pub struct DnsResult {
    pub ip: String,
    pub addr_type: i32,
    pub ttl: u32,
}

/// Look up a single IP result from the DNS cache for a (domain, qtype, group) key.
/// Called after query completion when the result should be in cache.
pub fn lookup_cache_result(c_domain: &CStr, qtype: i32, c_group: &CStr) -> Option<DnsResult> {
    unsafe {
        let mut key = smartdns_c::dns_cache_key {
            domain: c_domain.as_ptr(),
            qtype: qtype as smartdns_c::dns_type_t,
            dns_group_name: c_group.as_ptr(),
            query_flag: 0,
        };

        let cache = smartdns_c::dns_cache_lookup(&mut key);
        if cache.is_null() {
            return None;
        }

        let ttl = smartdns_c::dns_cache_get_ttl(cache) as u32;
        if ttl <= 0 {
            smartdns_c::dns_cache_release(cache);
            return None;
        }

        let data = smartdns_c::dns_cache_get_data(cache);
        if data.is_null() {
            smartdns_c::dns_cache_release(cache);
            return None;
        }

        // Cast cache_data to dns_cache_addr to read IP bytes
        let addr_data = data as *const smartdns_c::dns_cache_addr;
        let addr = &(*addr_data).addr_data;

        let ip_str = match qtype {
            DNS_T_A => {
                let ipv4_bytes = addr.__bindgen_anon_1.ipv4_addr.as_ref();
                let ipv4 = Ipv4Addr::from(*ipv4_bytes);
                ipv4.to_string()
            }
            DNS_T_AAAA => {
                let ipv6_bytes = addr.__bindgen_anon_1.ipv6_addr.as_ref();
                let ipv6 = Ipv6Addr::from(*ipv6_bytes);
                ipv6.to_string()
            }
            _ => {
                smartdns_c::dns_cache_release(cache);
                return None;
            }
        };

        smartdns_c::dns_cache_release(cache);

        Some(DnsResult {
            ip: ip_str,
            addr_type: qtype,
            ttl,
        })
    }
}

pub trait DnsRequest: Send + Sync {
    fn get_group_name(&self) -> String;
    fn get_domain(&self) -> String;
    fn get_qtype(&self) -> u32;
}

pub struct DnsRequest_C {
    request: *mut smartdns_c::dns_request,
}

impl DnsRequest_C {
    /// Wraps the request WITHOUT touching the C refcount — the C caller
    /// already holds a live reference. Used with `ManuallyDrop` to skip
    /// `dns_server_request_put` entirely on the C thread.
    pub fn new_borrowed(request: *mut smartdns_c::dns_request) -> DnsRequest_C {
        DnsRequest_C { request }
    }

    pub fn new(request: *mut smartdns_c::dns_request) -> DnsRequest_C {
        unsafe {
            smartdns_c::dns_server_request_get(request);
        }
        DnsRequest_C { request }
    }

    fn put_ref(&mut self) {
        unsafe {
            smartdns_c::dns_server_request_put(self.request);
            self.request = std::ptr::null_mut();
        }
    }
}

impl DnsRequest for DnsRequest_C {
    fn get_group_name(&self) -> String {
        unsafe {
            let group_name = smartdns_c::dns_server_request_get_group_name(self.request);
            if group_name.is_null() {
                return String::new();
            }
            std::ffi::CStr::from_ptr(group_name)
                .to_string_lossy()
                .into_owned()
        }
    }

    fn get_domain(&self) -> String {
        unsafe {
            let domain = smartdns_c::dns_server_request_get_domain(self.request);
            if domain.is_null() {
                return String::new();
            }
            std::ffi::CStr::from_ptr(domain)
                .to_string_lossy()
                .into_owned()
        }
    }

    fn get_qtype(&self) -> u32 {
        unsafe { smartdns_c::dns_server_request_get_qtype(self.request) as u32 }
    }
}

impl Drop for DnsRequest_C {
    fn drop(&mut self) {
        self.put_ref();
    }
}

unsafe impl Send for DnsRequest_C {}
unsafe impl Sync for DnsRequest_C {}

pub trait SmartdnsOperations {
    fn server_query_complete(&self, request: Box<dyn DnsRequest>);
    fn server_init(&mut self, args: &Vec<String>) -> Result<(), Box<dyn std::error::Error>>;
    fn server_exit(&mut self);
}

pub static mut PLUGIN: Plugin = Plugin {
    args: Vec::new(),
    ops: None,
};

pub struct Plugin {
    args: Vec<String>,
    ops: Option<Box<dyn SmartdnsOperations>>,
}

impl Plugin {
    pub fn get_args(&self) -> &Vec<String> {
        &self.args
    }

    pub fn set_operation(&mut self, ops: Box<dyn SmartdnsOperations>) {
        self.ops = Some(ops);
    }

    pub fn clear_operation(&mut self) {
        self.ops = None;
    }

    pub fn dns_conf_plugin_config(key: &str) -> Option<String> {
        let key = CString::new(key).expect("Failed to convert to CString");
        unsafe {
            let value = smartdns_c::smartdns_plugin_get_config(key.as_ptr());
            if value.is_null() {
                return None;
            }
            Some(
                std::ffi::CStr::from_ptr(value)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }

    fn parser_args(&mut self, plugin: *mut smartdns_c::dns_plugin) -> Result<(), String> {
        let argc = unsafe { smartdns_c::dns_plugin_get_argc(plugin) };
        let args: Vec<String> = unsafe {
            let argv = smartdns_c::dns_plugin_get_argv(plugin);
            let mut args = Vec::new();
            for i in 0..argc {
                let arg = std::ffi::CStr::from_ptr(*argv.offset(i as isize))
                    .to_string_lossy()
                    .into_owned();
                args.push(arg);
            }
            args
        };

        self.args = args;
        Ok(())
    }
}

static SMARTDNS_OPS: smartdns_c::smartdns_operations = smartdns_c::smartdns_operations {
    server_recv: None,
    server_query_complete: Some(dns_request_complete),
    server_log: None,
    server_audit_log: None,
};

#[no_mangle]
extern "C" fn dns_request_complete(request: *mut smartdns_c::dns_request) {
    unsafe {
        let plugin_addr = std::ptr::addr_of_mut!(PLUGIN);
        let ops = (*plugin_addr).ops.as_ref();
        if let None = ops {
            return;
        }

        let ops = ops.unwrap();
        let req = DnsRequest_C::new(request);
        ops.server_query_complete(Box::new(req));
    }
}

#[no_mangle]
extern "C" fn dns_plugin_init(plugin: *mut smartdns_c::dns_plugin) -> i32 {
    unsafe {
        let plugin_addr = std::ptr::addr_of_mut!(PLUGIN);
        if let Err(e) = (*plugin_addr).parser_args(plugin) {
            dns_log!(LogLevel::ERROR, "{}", e);
            return -1;
        }
        smartdns_c::smartdns_operations_register(&SMARTDNS_OPS);
        let ret = (*plugin_addr)
            .ops
            .as_mut()
            .unwrap()
            .server_init((*plugin_addr).get_args());
        if let Err(e) = ret {
            dns_log!(LogLevel::ERROR, "{}", e.to_string());
            return -1;
        }
    }

    return 0;
}

#[no_mangle]
extern "C" fn dns_plugin_exit(_plugin: *mut smartdns_c::dns_plugin) -> i32 {
    unsafe {
        let plugin_addr = std::ptr::addr_of_mut!(PLUGIN);
        smartdns_c::smartdns_operations_unregister(&SMARTDNS_OPS);
        if let Some(ops) = (*plugin_addr).ops.as_mut() {
            ops.server_exit();
        }
    }
    return 0;
}

#[no_mangle]
extern "C" fn dns_plugin_api_version() -> u32 {
    smartdns_c::SMARTDNS_PLUGIN_API_VERSION
}

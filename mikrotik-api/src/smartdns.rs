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
///
/// IMPORTANT: The cache data is always `dns_cache_packet` (raw DNS packet bytes),
/// NOT `dns_cache_addr`. The `dns_cache_addr` struct is defined in the header but
/// never actually used by the C code. Casting to it reads past the allocation,
/// causing SIGSEGV on small DNS packets.
///
/// Both `dns_cache_release(cache)` AND `dns_cache_data_put(data)` must be called
/// before returning to avoid refcount leaks.
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

        let cache_ttl = smartdns_c::dns_cache_get_ttl(cache) as u32;
        if cache_ttl == 0 {
            smartdns_c::dns_cache_release(cache);
            return None;
        }

        let data = smartdns_c::dns_cache_get_data(cache);
        if data.is_null() {
            smartdns_c::dns_cache_release(cache);
            return None;
        }

        // The cache data is always dns_cache_packet (raw DNS packet).
        // Layout: dns_cache_data_head (size field = packet_len), then packet bytes.
        let head = &(*data).head;
        let packet_len = head.size as usize;

        // Bounds check: packet must be at least DNS header size (12 bytes) and
        // must fit within the allocated data region.
        let head_size = std::mem::size_of::<smartdns_c::dns_cache_data_head>();
        if packet_len < 12 || packet_len > 65535 {
            smartdns_c::dns_cache_data_put(data);
            smartdns_c::dns_cache_release(cache);
            return None;
        }

        let packet_start = (data as *const u8).add(head_size);
        let packet_bytes = std::slice::from_raw_parts(packet_start, packet_len);

        let result = parse_dns_packet_for_ip(packet_bytes, qtype);

        smartdns_c::dns_cache_data_put(data);
        smartdns_c::dns_cache_release(cache);

        // Use cache_ttl (remaining cache lifetime) as the MikroTik timeout.
        // Do NOT use record_ttl — it can be 0 (common in DNS responses for
        // non-cacheable records), which would create a permanent entry in
        // MikroTik (timeout=0 = never expires) and cause repeated add attempts.
        result.map(|(ip, _record_ttl)| DnsResult {
            ip,
            addr_type: qtype,
            ttl: cache_ttl,
        })
    }
}

/// Parse a raw DNS response packet and extract the first A or AAAA record.
/// Returns (ip_string, record_ttl) or None.
fn parse_dns_packet_for_ip(packet: &[u8], qtype: i32) -> Option<(String, u32)> {
    // DNS header: 12 bytes
    if packet.len() < 12 {
        return None;
    }

    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;

    // Skip header (12 bytes)
    let mut pos: usize = 12;

    // Skip question section
    for _ in 0..qdcount {
        pos = skip_dns_name(packet, pos)?;
        // QTYPE (2) + QCLASS (2)
        pos = pos.checked_add(4)?;
    }

    // Parse answer section — find the first matching A or AAAA record
    for _ in 0..ancount {
        pos = skip_dns_name(packet, pos)?;

        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes minimum
        if pos + 10 > packet.len() {
            return None;
        }

        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let ttl = u32::from_be_bytes([
            packet[pos + 4],
            packet[pos + 5],
            packet[pos + 6],
            packet[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > packet.len() {
            return None;
        }

        let target_rtype = if qtype == DNS_T_A { 1u16 } else { 28u16 };
        if rtype == target_rtype {
            if qtype == DNS_T_A && rdlength == 4 {
                let ip = Ipv4Addr::new(
                    packet[pos],
                    packet[pos + 1],
                    packet[pos + 2],
                    packet[pos + 3],
                );
                return Some((ip.to_string(), ttl));
            } else if qtype == DNS_T_AAAA && rdlength == 16 {
                let ip = Ipv6Addr::from([
                    packet[pos], packet[pos + 1], packet[pos + 2], packet[pos + 3],
                    packet[pos + 4], packet[pos + 5], packet[pos + 6], packet[pos + 7],
                    packet[pos + 8], packet[pos + 9], packet[pos + 10], packet[pos + 11],
                    packet[pos + 12], packet[pos + 13], packet[pos + 14], packet[pos + 15],
                ]);
                return Some((ip.to_string(), ttl));
            }
        }

        pos = pos.checked_add(rdlength)?;
    }

    None
}

/// Skip a DNS name field (handles both labels and compression pointers).
fn skip_dns_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0u8;
    loop {
        if pos >= packet.len() {
            return None;
        }
        let b = packet[pos];
        if b == 0 {
            return Some(pos + 1);
        }
        if (b & 0xC0) == 0xC0 {
            // Compressed name pointer — 2 bytes total
            return Some(pos + 2);
        }
        let len = (b & 0x3F) as usize;
        pos = pos.checked_add(len + 1)?;
        jumps = jumps.checked_add(1)?;
        if jumps > 127 {
            return None; // prevent infinite loops from malformed packets
        }
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
    // catch_unwind prevents a Rust panic from unwinding through C frames,
    // which is undefined behavior and would crash the process.
    let _ = std::panic::catch_unwind(|| unsafe {
        let plugin_addr = std::ptr::addr_of_mut!(PLUGIN);
        let ops = (*plugin_addr).ops.as_ref();
        if ops.is_none() {
            return;
        }

        let ops = ops.unwrap();
        let req = DnsRequest_C::new(request);
        ops.server_query_complete(Box::new(req));
    });
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

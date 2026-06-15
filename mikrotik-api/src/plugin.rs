use crate::mikrotik_api::RosClient;
use crate::smartdns::*;
use std::error::Error;
use std::ffi::CString;
use std::mem::ManuallyDrop;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Instant;
use tokio::runtime::Builder;
use tokio::runtime::Runtime;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{timeout, Duration};

const IPV4_PATH: &str = "/ip/firewall/address-list";
const IPV6_PATH: &str = "/ipv6/firewall/address-list";
const DEFAULT_PORT: u16 = 8728;
const DEFAULT_SSL_PORT: u16 = 8729;
const CONNECTION_IDLE_TIMEOUT_SECS: u64 = 600;
const TASK_TIMEOUT_SECS: u64 = 30;

pub struct MikrotikPluginConfig {
    pub address: String,
    pub username: String,
    pub password: String,
    pub ssl: bool,
}

impl Default for MikrotikPluginConfig {
    fn default() -> Self {
        MikrotikPluginConfig {
            address: String::new(),
            username: String::new(),
            password: String::new(),
            ssl: false,
        }
    }
}

pub struct MikrotikPlugin {
    config: StdMutex<MikrotikPluginConfig>,
    connection: Mutex<Option<(Arc<RosClient>, Instant)>>,
    /// Serialise all RouterOS API commands to avoid internal actor races.
    device_sem: Semaphore,
    runtime: Arc<Runtime>,
}

impl MikrotikPlugin {
    pub fn new() -> Arc<Self> {
        let rt = Builder::new_multi_thread()
            .enable_all()
            .thread_name("mikrotik-api")
            .thread_keep_alive(Duration::from_secs(30))
            .build()
            .unwrap();

        Arc::new(MikrotikPlugin {
            config: StdMutex::new(MikrotikPluginConfig::default()),
            connection: Mutex::new(None),
            device_sem: Semaphore::new(1),
            runtime: Arc::new(rt),
        })
    }

    fn load_config(&self) -> Result<(), Box<dyn Error>> {
        let mut config = self.config.lock().unwrap();
        if let Some(addr) = Plugin::dns_conf_plugin_config("mikrotik-api.address") {
            config.address = addr;
        }
        if let Some(user) = Plugin::dns_conf_plugin_config("mikrotik-api.username") {
            config.username = user;
        }
        if let Some(pass) = Plugin::dns_conf_plugin_config("mikrotik-api.password") {
            config.password = pass;
        }
        if let Some(ssl_val) = Plugin::dns_conf_plugin_config("mikrotik-api.ssl") {
            config.ssl = ssl_val.eq_ignore_ascii_case("yes")
                || ssl_val == "1"
                || ssl_val.eq_ignore_ascii_case("true");
        }
        Ok(())
    }

    fn validate_config(&self) -> Result<(), String> {
        let cfg = self.config.lock().unwrap();
        if cfg.address.is_empty() {
            return Err("mikrotik-api.address is not configured".into());
        }
        if cfg.username.is_empty() {
            return Err("mikrotik-api.username is not configured".into());
        }
        if cfg.password.is_empty() {
            return Err("mikrotik-api.password is not configured".into());
        }
        Ok(())
    }

    pub fn start(&self, _args: &Vec<String>) -> Result<(), Box<dyn Error>> {
        self.load_config()?;
        self.validate_config()?;
        Ok(())
    }

    pub fn stop(&self) {}

    /// Return cached connection or create a new one.
    /// Lock is held only briefly; a small race window on cache-miss is harmless.
    async fn get_or_connect(self: &Arc<Self>) -> Result<Arc<RosClient>, String> {
        {
            let guard = self.connection.lock().await;
            if let Some((ref c, t)) = *guard {
                if t.elapsed().as_secs() < CONNECTION_IDLE_TIMEOUT_SECS {
                    return Ok(Arc::clone(c));
                }
            }
        }

        let (host, port, username, password) = {
            let cfg = self.config.lock().unwrap();
            let (h, p) = parse_address(&cfg.address, cfg.ssl);
            (h, p, cfg.username.clone(), cfg.password.clone())
        };

        let client = RosClient::connect_and_login(&host, port, &username, &password)
            .await
            .map_err(|e| e.to_string())?;
        let client = Arc::new(client);

        let mut guard = self.connection.lock().await;
        *guard = Some((Arc::clone(&client), Instant::now()));
        Ok(client)
    }

    pub fn query_complete(self: &Arc<Self>, request: Box<dyn DnsRequest>) {
        // NEVER drop request on the C thread — ManuallyDrop skips the
        // DnsRequest_C destructor (dns_server_request_put) which could
        // reach back into C request cleanup from the wrong context.
        let request = ManuallyDrop::new(request);

        let group_name = request.get_group_name();
        let domain = request.get_domain();
        let qtype = request.get_qtype() as i32;

        if group_name.is_empty() || group_name == "default" {
            return;
        }
        if qtype != DNS_T_A && qtype != DNS_T_AAAA {
            return;
        }

        // Do cache lookup HERE on the C thread — safe, no cross-thread races.
        let c_domain = match CString::new(domain.as_bytes()) { Ok(c) => c, Err(_) => return };
        let c_group = match CString::new(group_name.as_bytes()) { Ok(c) => c, Err(_) => return };

        let result = match lookup_cache_result(&c_domain, qtype, &c_group) {
            Some(r) => r,
            None => return,
        };
        if !is_valid_ip(&result.ip) {
            return;
        }

        let ip_path = if result.addr_type == DNS_T_A { IPV4_PATH } else { IPV6_PATH };
        let ip = result.ip;
        let ttl = result.ttl;

        let self_clone = Arc::clone(self);

        self.runtime.spawn(async move {
            let _ = timeout(Duration::from_secs(TASK_TIMEOUT_SECS), async {
                let client = self_clone.get_or_connect().await.ok()?;
                let _permit = self_clone.device_sem.acquire().await.ok()?;
                let _ = sync_address_list_entry(&client, ip_path, &group_name, &ip, ttl).await;
                Some(())
            })
            .await;
        });
    }
}

fn is_valid_ip(ip: &str) -> bool {
    if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
        if ipv4.is_unspecified() || ipv4.is_loopback() || ipv4.is_multicast() || ipv4.is_broadcast() {
            return false;
        }
        let o = ipv4.octets();
        if o[0] == 0 {
            return false;
        }
        if o[0] == 100 {
            return false;
        }
        if o[0] == 169 && o[1] == 254 {
            return false;
        }
        if o[0] == 192 && o[1] == 0 && o[2] == 2 {
            return false;
        }
        if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
            return false;
        }
        if o[0] == 198 && o[1] == 51 && o[2] == 100 {
            return false;
        }
        if o[0] == 203 && o[1] == 0 && o[2] == 113 {
            return false;
        }
        if o[0] >= 240 {
            return false;
        }
        return true;
    }
    if let Ok(ipv6) = ip.parse::<Ipv6Addr>() {
        if ipv6.is_unspecified() || ipv6.is_loopback() || ipv6.is_multicast() {
            return false;
        }
        let s = ipv6.segments();
        if s[0] & 0xffc0 == 0xfe80 {
            return false;
        }
        return true;
    }
    false
}

async fn sync_address_list_entry(
    client: &Arc<RosClient>,
    ip_path: &str,
    list: &str,
    address: &str,
    ttl: u32,
) -> Result<(), String> {
    let entry_id = client
        .find_entry_id(ip_path, list, address)
        .await
        .map_err(|e| e.to_string())?;

    match entry_id {
        Some(id) => {
            if let Ok(Some(existing)) = client.get_entry_timeout(ip_path, &id).await {
                if ttl > existing {
                    client
                        .update_address_list_timeout(ip_path, &id, ttl)
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        None => {
            client
                .add_address_list_entry(ip_path, list, address, ttl)
                .await
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn parse_address(address: &str, ssl: bool) -> (String, u16) {
    let dp = if ssl { DEFAULT_SSL_PORT } else { DEFAULT_PORT };
    if let Some(ci) = address.rfind(':') {
        if let Some(bi) = address.rfind(']') {
            if bi < ci {
                let h = &address[1..bi];
                if let Ok(p) = address[ci + 1..].parse() {
                    return (h.into(), p);
                }
            }
        }
        let before = &address[..ci];
        if !before.contains(':') {
            if let Ok(p) = address[ci + 1..].parse() {
                return (before.into(), p);
            }
        }
    }
    (address.into(), dp)
}

pub struct MikrotikPluginImpl {
    plugin: Arc<MikrotikPlugin>,
}

impl MikrotikPluginImpl {
    pub fn new() -> Self {
        MikrotikPluginImpl {
            plugin: MikrotikPlugin::new(),
        }
    }
}

impl SmartdnsOperations for MikrotikPluginImpl {
    fn server_query_complete(&self, request: Box<dyn DnsRequest>) {
        self.plugin.query_complete(request);
    }

    fn server_init(&mut self, args: &Vec<String>) -> Result<(), Box<dyn Error>> {
        self.plugin.start(args)
    }

    fn server_exit(&mut self) {
        self.plugin.stop();
    }
}

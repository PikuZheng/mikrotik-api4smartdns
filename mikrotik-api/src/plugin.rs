use crate::dns_log;
use crate::mikrotik_api::{AddOutcome, PipelineEntry, RosClient};
use crate::smartdns::*;
use std::collections::HashMap;
use std::error::Error;
use std::ffi::CString;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::runtime::Builder;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration, Instant};

const IPV4_PATH: &str = "/ip/firewall/address-list";
const IPV6_PATH: &str = "/ipv6/firewall/address-list";
const DEFAULT_PORT: u16 = 8728;
const DEFAULT_SSL_PORT: u16 = 8729;
const QUEUE_CAPACITY: usize = 65536;
const FLUSH_INTERVAL_MS: u64 = 200;
const PIPELINE_SIZE: usize = 64;
const RECONNECT_MIN_DELAY_SECS: u64 = 1;
const RECONNECT_MAX_DELAY_SECS: u64 = 30;

/// Resolved result — IP and TTL are looked up from cache on the C callback thread.
#[derive(Clone, Debug)]
struct ResolvedJob {
    group: String,
    ip: String,
    ttl: u32,
    qtype: i32,
}

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
    tx: StdMutex<Option<mpsc::Sender<ResolvedJob>>>,
    runtime: Arc<Runtime>,
    rx: StdMutex<Option<mpsc::Receiver<ResolvedJob>>>,
}

impl MikrotikPlugin {
    pub fn new() -> Arc<Self> {
        let rt = Builder::new_multi_thread()
            .enable_all()
            .thread_name("mikrotik-api")
            .thread_keep_alive(Duration::from_secs(30))
            .build()
            .unwrap();

        let (tx, rx) = mpsc::channel::<ResolvedJob>(QUEUE_CAPACITY);

        let plugin = Arc::new(MikrotikPlugin {
            config: StdMutex::new(MikrotikPluginConfig::default()),
            tx: StdMutex::new(Some(tx)),
            runtime: Arc::new(rt),
            rx: StdMutex::new(Some(rx)),
        });

        plugin
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

        let (host, port, username, password) = {
            let cfg = self.config.lock().unwrap();
            let (h, p) = parse_address(&cfg.address, cfg.ssl);
            (h, p, cfg.username.clone(), cfg.password.clone())
        };

        let rx = self.rx.lock().unwrap().take();
        if let Some(rx) = rx {
            self.runtime.spawn(async move {
                worker(rx, host, port, username, password).await;
            });
        }

        Ok(())
    }

    pub fn stop(&self) {
        // Drop the sender to close the channel, signaling the worker to exit.
        self.tx.lock().unwrap().take();
    }

    /// Called from the smartdns C callback thread.
    /// IMPORTANT: dns_cache_lookup MUST be called here (on the main thread),
    /// NOT from the tokio worker. Calling it from another thread causes
    /// severe lock contention and can crash smartdns.
    pub fn query_complete(self: &Arc<Self>, request: Box<dyn DnsRequest>) {
        let group_name = request.get_group_name();
        let domain = request.get_domain();
        let qtype = request.get_qtype() as i32;

        if group_name.is_empty() || group_name == "default" {
            return;
        }
        if qtype != DNS_T_A && qtype != DNS_T_AAAA {
            return;
        }

        // Look up cache result RIGHT HERE on the C callback thread.
        let c_domain = match CString::new(domain.as_bytes()) {
            Ok(c) => c,
            Err(_) => return,
        };
        let c_group = match CString::new(group_name.as_bytes()) {
            Ok(c) => c,
            Err(_) => return,
        };

        let result = match lookup_cache_result(&c_domain, qtype, &c_group) {
            Some(r) => r,
            None => return,
        };

        if !is_valid_ip(&result.ip) {
            return;
        }

        if let Some(tx) = self.tx.lock().unwrap().as_ref() {
            let _ = tx.try_send(ResolvedJob {
                group: group_name,
                ip: result.ip,
                ttl: result.ttl,
                qtype,
            });
        }
    }
}

/// Worker loop: receives resolved jobs, batches, deduplicates, and sends to Mikrotik.
/// Runs as a single async task — all RouterOS I/O is serialised through here.
async fn worker(
    mut rx: mpsc::Receiver<ResolvedJob>,
    host: String,
    port: u16,
    username: String,
    password: String,
) {
    let mut client: Option<RosClient> = None;
    let mut reconnect_delay = RECONNECT_MIN_DELAY_SECS;
    // Local cache: tracks (group, ip) -> ttl as last confirmed in Mikrotik.
    // Allows skipping add for entries that already exist with sufficient TTL.
    let mut local_cache: HashMap<(String, String), u32> = HashMap::new();

    loop {
        // Phase 1: Collect batch within flush interval
        let mut batch: HashMap<(String, String), (u32, i32)> = HashMap::new();
        let deadline = Instant::now() + Duration::from_millis(FLUSH_INTERVAL_MS);

        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(job)) => {
                    let key = (job.group, job.ip);
                    match batch.get_mut(&key) {
                        Some((ttl, _)) if job.ttl > *ttl => *ttl = job.ttl,
                        Some(_) => {}
                        None => {
                            batch.insert(key, (job.ttl, job.qtype));
                        }
                    }
                }
                Ok(None) => return, // channel closed — shutdown
                Err(_) => break,   // deadline reached
            }
        }

        if batch.is_empty() {
            continue;
        }

        // Phase 2: Filter with local cache — skip entries already in Mikrotik with >= TTL
        batch.retain(|key, (ttl, _)| match local_cache.get(key) {
            Some(cached_ttl) if *cached_ttl >= *ttl => false,
            _ => true,
        });

        if batch.is_empty() {
            continue;
        }

        // Phase 3: Ensure connection
        if client.is_none() {
            match RosClient::connect_and_login(&host, port, &username, &password).await {
                Ok(c) => {
                    client = Some(c);
                    reconnect_delay = RECONNECT_MIN_DELAY_SECS;
                    // Local cache may be stale after reconnect; clear and rebuild.
                    // Entries already in Mikrotik will produce Duplicate and be re-cached.
                    local_cache.clear();
                    dns_log!(LogLevel::INFO, "mikrotik-api: connected to {}:{}", host, port);
                }
                Err(e) => {
                    dns_log!(LogLevel::ERROR, "mikrotik-api: connect failed: {}", e);
                    sleep(Duration::from_secs(reconnect_delay)).await;
                    reconnect_delay = (reconnect_delay * 2).min(RECONNECT_MAX_DELAY_SECS);
                    continue;
                }
            }
        }

        // Phase 4: Pipeline-add entries in chunks
        let entries: Vec<_> = batch.into_iter().collect();
        let mut cache_updates: Vec<((String, String), u32)> = Vec::new();
        let mut connection_ok = true;

        for chunk in entries.chunks(PIPELINE_SIZE) {
            let pipeline_entries: Vec<PipelineEntry> = chunk
                .iter()
                .map(|((group, ip), (ttl, qtype))| {
                    let ip_path = if *qtype == DNS_T_A {
                        IPV4_PATH
                    } else {
                        IPV6_PATH
                    };
                    PipelineEntry {
                        ip_path,
                        list: group,
                        address: ip,
                        ttl: *ttl,
                    }
                })
                .collect();

            let results = client.as_ref().unwrap().pipeline_add(&pipeline_entries).await;

            for (((group, ip), (ttl, _)), result) in chunk.iter().zip(results.iter()) {
                match result {
                    Ok(AddOutcome::Added) | Ok(AddOutcome::Duplicate) => {
                        cache_updates.push(((group.clone(), ip.clone()), *ttl));
                    }
                    Err(e) => {
                        dns_log!(
                            LogLevel::WARN,
                            "mikrotik-api: add failed for {}/{}: {}",
                            group,
                            ip,
                            e
                        );
                        connection_ok = false;
                    }
                }
            }

            if !connection_ok {
                break;
            }
        }

        // Update local cache only for successful entries
        for (key, ttl) in cache_updates {
            local_cache.insert(key, ttl);
        }

        // Periodically evict stale entries from local cache to bound memory.
        // Simple approach: if cache is too large, clear it (will rebuild naturally).
        if local_cache.len() > 100_000 {
            local_cache.clear();
        }

        // Handle connection errors — reconnect with exponential backoff
        if !connection_ok {
            dns_log!(LogLevel::WARN, "mikrotik-api: connection error, will reconnect");
            client = None;
            sleep(Duration::from_secs(reconnect_delay)).await;
            reconnect_delay = (reconnect_delay * 2).min(RECONNECT_MAX_DELAY_SECS);
        } else {
            reconnect_delay = RECONNECT_MIN_DELAY_SECS;
        }
    }
}

fn is_valid_ip(ip: &str) -> bool {
    if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
        if ipv4.is_unspecified() || ipv4.is_loopback() || ipv4.is_multicast() || ipv4.is_broadcast()
        {
            return false;
        }
        let o = ipv4.octets();
        if o[0] == 0 || o[0] == 100 {
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

fn parse_address(address: &str, ssl: bool) -> (String, u16) {
    let dp = if ssl {
        DEFAULT_SSL_PORT
    } else {
        DEFAULT_PORT
    };
    if let Some(ci) = address.rfind(':') {
        if let Some(bi) = address.rfind(']') {
            if bi < ci {
                if let Ok(p) = address[ci + 1..].parse() {
                    return (address[1..bi].into(), p);
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

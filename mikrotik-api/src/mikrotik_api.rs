use mikrotik_rs::{CommandBuilder, Event, MikrotikDevice};
use std::io;
use std::net::SocketAddr;

/// Outcome of an add operation.
#[derive(Debug, Clone, PartialEq)]
pub enum AddOutcome {
    Added,
    Duplicate,
}

/// A single entry for pipeline batch-add.
pub struct PipelineEntry<'a> {
    pub ip_path: &'a str,
    pub list: &'a str,
    pub address: &'a str,
    pub domain: &'a str,
    pub ttl: u32,
}

/// RouterOS API client wrapping mikrotik-rs.
pub struct RosClient {
    device: MikrotikDevice,
}

impl RosClient {
    /// Connect to RouterOS API and authenticate.
    /// Supports both IPv4 (e.g. "192.168.1.1:8728") and IPv6 (e.g. "[fe80::1]:8729").
    pub async fn connect_and_login(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> io::Result<Self> {
        // IPv6 addresses must be enclosed in brackets for SocketAddr parsing
        let addr_str = if host.contains(':') {
            format!("[{}]:{}", host, port)
        } else {
            format!("{}:{}", host, port)
        };
        let _addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let device = MikrotikDevice::connect(&addr_str, username, Some(password))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(RosClient { device })
    }

    /// Add a single address-list entry. Returns Duplicate on Trap (entry already exists).
    pub async fn add_entry(
        &self,
        ip_path: &str,
        list: &str,
        address: &str,
        domain: &str,
        ttl: u32,
    ) -> io::Result<AddOutcome> {
        let ttl_str = ttl.to_string();
        let comment = format!("smartdns: {}", domain);
        let path = format!("{}/add", ip_path);
        let cmd = CommandBuilder::new()
            .command(&path)
            .attribute("list", Some(list))
            .attribute("address", Some(address))
            .attribute("timeout", Some(&ttl_str))
            .attribute("comment", Some(&comment))
            .build();

        let mut rx = self.device.send_command(cmd).await.map_err(other_err)?;

        while let Some(event) = rx.recv().await {
            match event {
                Event::Done { .. } => return Ok(AddOutcome::Added),
                Event::Trap { .. } => return Ok(AddOutcome::Duplicate),
                Event::Fatal { .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "fatal error from RouterOS",
                    ))
                }
                Event::Reply { .. } => {} // add may return reply with new item ID
                Event::Empty { .. } => {}
            }
        }
        Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "connection closed without response",
        ))
    }

    /// Pipeline batch-add: send N add commands, then collect N results.
    /// Returns one result per entry, in the same order.
    pub async fn pipeline_add<'a>(
        &self,
        entries: &[PipelineEntry<'a>],
    ) -> Vec<io::Result<AddOutcome>> {
        let len = entries.len();
        // Use Vec<Option<...>> so we can fill results out of order by index
        let mut results: Vec<Option<io::Result<AddOutcome>>> = Vec::with_capacity(len);
        results.resize_with(len, || None);

        // Phase 1: Send all commands, collect receivers paired with their index.
        let mut receivers: Vec<(usize, _)> = Vec::with_capacity(len);
        let mut connection_broken = false;

        for (i, entry) in entries.iter().enumerate() {
            if connection_broken {
                results[i] = Some(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "skipped: connection broken during pipeline",
                )));
                continue;
            }

            let comment = format!("smartdns: {}", entry.domain);
            let ttl_str = entry.ttl.to_string();
            let path = format!("{}/add", entry.ip_path);
            let cmd = CommandBuilder::new()
                .command(&path)
                .attribute("list", Some(entry.list))
                .attribute("address", Some(entry.address))
                .attribute("timeout", Some(&ttl_str))
                .attribute("comment", Some(&comment))
                .build();

            match self.device.send_command(cmd).await {
                Ok(rx) => receivers.push((i, rx)),
                Err(e) => {
                    connection_broken = true;
                    results[i] = Some(Err(other_err(e)));
                }
            }
        }

        // Phase 2: Collect results from all receivers.
        for (i, mut rx) in receivers {
            let mut outcome = Ok(AddOutcome::Added);
            let mut got_response = false;

            while let Some(event) = rx.recv().await {
                match event {
                    Event::Done { .. } => {
                        got_response = true;
                        break;
                    }
                    Event::Trap { .. } => {
                        outcome = Ok(AddOutcome::Duplicate);
                        got_response = true;
                        break;
                    }
                    Event::Fatal { .. } => {
                        outcome = Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "fatal error from RouterOS",
                        ));
                        got_response = true;
                        break;
                    }
                    Event::Reply { .. } => {} // ignore intermediate replies
                    Event::Empty { .. } => {}
                }
            }

            if !got_response {
                outcome = Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "connection closed without response",
                ));
            }

            results[i] = Some(outcome);
        }

        results.into_iter().map(|r| r.unwrap()).collect()
    }

    /// Find entry ID by list + address. Returns None if not found.
    pub async fn find_entry_id(
        &self,
        ip_path: &str,
        list: &str,
        address: &str,
    ) -> io::Result<Option<String>> {
        let path = format!("{}/find", ip_path);
        let cmd = CommandBuilder::new()
            .command(&path)
            .query_equal("list", list)
            .query_equal("address", address)
            .build();

        let mut rx = self.device.send_command(cmd).await.map_err(other_err)?;
        let mut found_id = None;

        while let Some(event) = rx.recv().await {
            match event {
                Event::Reply { response, .. } => {
                    if let Some(Some(id)) = response.attributes.get(".id") {
                        found_id = Some(id.clone());
                        // Continue draining to consume the Done event
                    }
                }
                Event::Trap { .. } | Event::Fatal { .. } | Event::Done { .. } => break,
                _ => {}
            }
        }
        Ok(found_id)
    }

    /// Update timeout of an existing entry.
    pub async fn update_timeout(
        &self,
        ip_path: &str,
        entry_id: &str,
        ttl: u32,
    ) -> io::Result<()> {
        let ttl_str = ttl.to_string();
        let path = format!("{}/set", ip_path);
        let cmd = CommandBuilder::new()
            .command(&path)
            .attribute(".id", Some(entry_id))
            .attribute("timeout", Some(&ttl_str))
            .attribute("comment", Some("smartdns"))
            .build();

        let mut rx = self.device.send_command(cmd).await.map_err(other_err)?;

        while let Some(event) = rx.recv().await {
            if matches!(
                event,
                Event::Done { .. } | Event::Trap { .. } | Event::Fatal { .. }
            ) {
                break;
            }
        }
        Ok(())
    }
}

fn other_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

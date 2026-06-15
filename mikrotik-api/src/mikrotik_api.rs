use mikrotik_rs::{CommandBuilder, Event, MikrotikDevice};
use std::io;

/// RouterOS API client wrapping mikrotik-rs v0.8.
/// Only `send_command` failing (device dead) returns Err; Trap/Done are normal.
pub struct RosClient {
    device: MikrotikDevice,
}

impl RosClient {
    pub async fn connect_and_login(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> io::Result<Self> {
        let addr = format!("{}:{}", host, port);
        let device = MikrotikDevice::connect(&addr, username, Some(password))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(RosClient { device })
    }

    /// Returns Some(id) if found, None otherwise. Trap → treated as "not found".
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

        while let Some(event) = rx.recv().await {
            match event {
                Event::Reply { response, .. } => {
                    if let Some(Some(id)) = response.attributes.get(".id") {
                        return Ok(Some(id.clone()));
                    }
                }
                Event::Trap { .. } | Event::Fatal { .. } => break,
                Event::Done { .. } => break,
                _ => {}
            }
        }
        Ok(None)
    }

    /// Returns Some(timeout) if found, None otherwise.
    pub async fn get_entry_timeout(
        &self,
        ip_path: &str,
        entry_id: &str,
    ) -> io::Result<Option<u32>> {
        let path = format!("{}/print", ip_path);
        let cmd = CommandBuilder::new()
            .command(&path)
            .query_equal(".id", entry_id)
            .attribute(".proplist", Some("timeout"))
            .build();

        let mut rx = self.device.send_command(cmd).await.map_err(other_err)?;

        while let Some(event) = rx.recv().await {
            match event {
                Event::Reply { response, .. } => {
                    if let Some(Some(timeout_str)) = response.attributes.get("timeout") {
                        if let Ok(timeout) = timeout_str.parse::<u32>() {
                            return Ok(Some(timeout));
                        }
                    }
                }
                Event::Done { .. } => break,
                Event::Trap { .. } | Event::Fatal { .. } => break,
                _ => {}
            }
        }
        Ok(None)
    }

    /// Add entry. Trap (e.g. already exists) is silently ignored.
    pub async fn add_address_list_entry(
        &self,
        ip_path: &str,
        list: &str,
        address: &str,
        ttl: u32,
    ) -> io::Result<()> {
        let ttl_str = ttl.to_string();
        let path = format!("{}/add", ip_path);
        let cmd = CommandBuilder::new()
            .command(&path)
            .attribute("list", Some(list))
            .attribute("address", Some(address))
            .attribute("timeout", Some(&ttl_str))
            .attribute("comment", Some("smartdns"))
            .build();

        let mut rx = self.device.send_command(cmd).await.map_err(other_err)?;

        while let Some(event) = rx.recv().await {
            if matches!(event, Event::Done { .. } | Event::Trap { .. } | Event::Fatal { .. }) {
                break;
            }
        }
        Ok(())
    }

    /// Update timeout. Trap (e.g. entry disappeared) is silently ignored.
    pub async fn update_address_list_timeout(
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
            if matches!(event, Event::Done { .. } | Event::Trap { .. } | Event::Fatal { .. }) {
                break;
            }
        }
        Ok(())
    }
}

fn other_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

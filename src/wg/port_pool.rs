use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use rand::Rng;

pub struct LocalPortPool {
    used_ports: Arc<Mutex<HashSet<u16>>>,
}

impl LocalPortPool {
    const MIN_PORT: u16 = 49152;

    const MAX_PORT: u16 = 65535;

    pub fn default() -> Self {
        Self {
            used_ports: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn next(&self) -> LocalPort {
        let mut used_ports = self.used_ports.lock().unwrap();
        let mut rng = rand::thread_rng();
        loop {
            let local_port = rng.gen_range(Self::MIN_PORT..Self::MAX_PORT);
            if !used_ports.contains(&local_port) {
                used_ports.insert(local_port);
                break LocalPort {
                    used_ports: self.used_ports.clone(),
                    port: local_port,
                };
            }
        }
    }
}

pub struct LocalPort {
    port: u16,
    used_ports: Arc<Mutex<HashSet<u16>>>,
}

impl LocalPort {
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for LocalPort {
    fn drop(&mut self) {
        self.used_ports.lock().unwrap().remove(&self.port);
    }
}

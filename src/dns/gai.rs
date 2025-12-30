use hyper::client::connect::dns::{GaiResolver as HyperGaiResolver, Name};
use hyper::service::Service;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::dns::{Addrs, Resolve, Resolving};
use crate::error::BoxError;

#[derive(Debug, Clone)]
struct CacheEntry {
    addrs: Vec<SocketAddr>,
    timestamp: Instant,
}

impl CacheEntry {
    fn new(addrs: Vec<SocketAddr>) -> Self {
        Self {
            addrs,
            timestamp: Instant::now(),
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.timestamp.elapsed() > ttl
    }
}

#[derive(Debug)]
pub struct GaiResolver {
    inner: HyperGaiResolver,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    ttl: Duration,
}

impl GaiResolver {
    pub fn new() -> Self {
        Self {
            inner: HyperGaiResolver::new(),
            cache: Arc::new(Mutex::new(HashMap::new())),
            ttl: Duration::from_secs(300), // 5 minutes default TTL
        }
    }
}

impl Default for GaiResolver {
    fn default() -> Self {
        GaiResolver::new()
    }
}

impl Resolve for GaiResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let name_str = name.as_str().to_string();
        let cache = Arc::clone(&self.cache);
        let ttl = self.ttl;
        let mut inner = self.inner.clone();

        // Check cache first
        let cache_check = {
            let cache_guard = cache.lock().unwrap();
            cache_guard.get(&name_str).and_then(|entry| {
                if !entry.is_expired(ttl) {
                    Some(entry.addrs.clone())
                } else {
                    None
                }
            })
        };

        // Return cached result if available and not expired
        if let Some(addrs) = cache_check {
            let addrs_boxed: Addrs = Box::new(addrs.into_iter());
            return Box::pin(futures_util::future::ready(Ok(addrs_boxed)));
        }

        // Not in cache or expired, perform DNS resolution
        Box::pin(async move {
            let result = Service::<Name>::call(&mut inner, name).await;
            
            match result {
                Ok(addrs) => {
                    let addrs_vec: Vec<SocketAddr> = addrs.collect();
                    
                    // Cache the result
                    let cache_entry = CacheEntry::new(addrs_vec.clone());
                    {
                        let mut cache_guard = cache.lock().unwrap();
                        cache_guard.insert(name_str, cache_entry);
                    }
                    
                    Ok(Box::new(addrs_vec.into_iter()) as Addrs)
                }
                Err(err) => Err(Box::new(err) as BoxError),
            }
        })
    }
}

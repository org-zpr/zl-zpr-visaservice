//! Redis/ValKey operations related to nodes (as distinct from actors).
//!
//!
//! This updates:
//! - node:<ZADDR>             - a json Node struct -- metadata about a node connection.
//! - node:<ZADDR>:lastseen    - timestamp of last contact from the node
//! - node:<ZADDR>:vss         - a json SAWrapper struct -- the VSS address for the node.
//! - node:<ZADDR>:connections - a set of adapter addresses connected to the node.
//!
//! Future stuff (not yet implemented):
//! - node:<ZADDR>:todo:vinstall - ordered list of visa IDs to be installed on the node
//! - node:<ZADDR>:todo:vrevoke - ordered list of visa IDs to be revoked from the node
//! - node:<ZADDR>:todo:crevoke - ordered list of authentication IDs (TBD??) to be revoked from the node

use chrono::Utc;
use libeval::actor::Actor;
use libeval::attribute::key;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::debug;

use crate::db::{DbConnection, DbOp, ZAddr};
use crate::error::StoreError;
use crate::logging::targets::DB;

// We keep this whole thing as JSON in node:<ZADDR>
#[derive(Debug, Serialize, Deserialize)]
pub struct Node {
    pub ctime: SystemTime,
    pub zpr_addr: IpAddr,
    pub cn: String,
    /// The node's substrate address claim: policy's, else the relay's observation
    /// (zl-zipline#264). `None` when there is neither, as for a relay with no policy
    /// address, which needs none.
    pub substrate_addr: Option<SocketAddr>,
}

// Wrap a SocketAddr for easy serialization.
#[derive(Debug, Serialize, Deserialize)]
struct SAWrapper {
    pub vss_addr: SocketAddr,
}

pub struct NodeRepo {
    db: Arc<dyn DbConnection>,
}

impl NodeRepo {
    pub fn new(db: Arc<dyn DbConnection>) -> Self {
        NodeRepo { db }
    }

    /// Add/overwrite the node state record.
    ///
    /// A node record is assoicated with an actor that is a node role.
    /// Nodes authenticate with the visa service directly.
    /// One node is also the visa service's dock.
    pub async fn add_node(&self, node: &Node) -> Result<(), StoreError> {
        //
        // node:<ZADDR> -> string, json formatted Node struct.
        //
        self.db
            .set(
                &node_key_for_node(&node.zpr_addr),
                &serde_json::to_string(&node)?,
            )
            .await?;
        Ok(())
    }

    /// Keep track of the VSS address for the node.
    pub async fn set_node_vss(
        &self,
        node_zpr_addr: &IpAddr,
        vss_addr: &SocketAddr,
    ) -> Result<(), StoreError> {
        let does_exist: bool = self.db.exists(&node_key_for_node(node_zpr_addr)).await?;
        if !does_exist {
            return Err(StoreError::NotFound(format!(
                "node not found for address {}",
                node_zpr_addr
            )));
        }
        self.db
            .set(
                &vss_key_for_node(node_zpr_addr),
                &serde_json::to_string(&SAWrapper {
                    vss_addr: *vss_addr,
                })?,
            )
            .await?;
        Ok(())
    }

    /// Get the VSS address for the node, if any.
    pub async fn get_node_vss(
        &self,
        node_zpr_addr: &IpAddr,
    ) -> Result<Option<SocketAddr>, StoreError> {
        let vss_json_opt = self.db.get(&vss_key_for_node(node_zpr_addr)).await?;
        if let Some(vss_json) = vss_json_opt {
            let sa_wrapper: SAWrapper = serde_json::from_str(&vss_json)?;
            Ok(Some(sa_wrapper.vss_addr))
        } else {
            Ok(None)
        }
    }

    /// Drop the vss info for the node.
    pub async fn clear_node_vss(&self, node_zpr_addr: &IpAddr) -> Result<(), StoreError> {
        self.db.del(&vss_key_for_node(node_zpr_addr)).await?;
        Ok(())
    }

    /// Update the last seen time for the node to now.
    pub async fn update_last_seen_time(&self, node_zpr_addr: &IpAddr) -> Result<(), StoreError> {
        // store as a chrono string.
        let now = Utc::now().to_rfc3339();
        self.db
            .set(&lastseen_key_for_node(node_zpr_addr), &now)
            .await?;
        Ok(())
    }

    /// Get the last seen time for the node, if recorded.
    pub async fn get_last_seen_time(
        &self,
        node_zpr_addr: &IpAddr,
    ) -> Result<Option<SystemTime>, StoreError> {
        let Some(ts_str) = self.db.get(&lastseen_key_for_node(node_zpr_addr)).await? else {
            return Ok(None);
        };
        let dt = chrono::DateTime::parse_from_rfc3339(&ts_str).map_err(|e| {
            StoreError::InvalidData(format!("failed to parse last-seen timestamp: {}", e))
        })?;
        Ok(Some(SystemTime::from(dt)))
    }

    /// Add state that an adapter is connected to a node.
    pub async fn add_connected_adater(
        &self,
        node_addr: &IpAddr,
        adapter_addr: &IpAddr,
    ) -> Result<(), StoreError> {
        //
        // node:<ZADDR>:connections -> SET [ <zpr_address as string> ]
        //
        self.db
            .sadd(
                &connections_key_for_node(node_addr),
                &adapter_addr.to_string(),
            )
            .await?;
        Ok(())
    }

    /// Remove the state that an adapter is connected to a node.
    pub async fn remove_connected_adapter(
        &self,
        node_addr: &IpAddr,
        adapter_addr: &IpAddr,
    ) -> Result<(), StoreError> {
        let ops = vec![DbOp::SRem {
            set_key: connections_key_for_node(node_addr),
            member: adapter_addr.to_string(),
        }];
        self.db.atomic_pipeline(&ops).await?;
        Ok(())
    }

    /// Get the list of adapter addresses connected to the given node.
    pub async fn get_connected_adapters(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Vec<IpAddr>, StoreError> {
        let adapter_zaddr_strings = self
            .db
            .smembers(&connections_key_for_node(node_addr))
            .await?;
        // convert to IpAddr - bad parse causes error
        let mut adapter_addrs = Vec::new();
        for addr_str in adapter_zaddr_strings {
            match addr_str.parse::<IpAddr>() {
                Ok(addr) => adapter_addrs.push(addr),
                Err(e) => {
                    return Err(StoreError::InvalidData(format!(
                        "failed to parse address string '{}' as IpAddr: {}",
                        addr_str, e
                    )));
                }
            }
        }
        Ok(adapter_addrs)
    }

    /// Removes all the ancillary node tables.
    pub async fn remove_node(&self, node_addr: &IpAddr) -> Result<(), StoreError> {
        let ops = vec![
            DbOp::Del(connections_key_for_node(node_addr)),
            DbOp::Del(todo_vinstall_key_for_node(node_addr)),
            DbOp::Del(todo_vrevoke_key_for_node(node_addr)),
            DbOp::Del(todo_crevoke_key_for_node(node_addr)),
            DbOp::Del(node_key_for_node(node_addr)),
            DbOp::Del(vss_key_for_node(node_addr)),
            DbOp::Del(lastseen_key_for_node(node_addr)),
        ];
        self.db.atomic_pipeline(&ops).await?;
        debug!(target: DB, "removed node state for node at addr {}", node_addr);
        Ok(())
    }

    /// The the list of node ZPR addresses.
    pub async fn list_node_addrs(&self) -> Result<Vec<IpAddr>, StoreError> {
        let keys = self.db.scan_match_all("node:*".into()).await?;
        let mut addrs = Vec::new();
        for key in keys {
            if let Some(stripped) = key.strip_prefix("node:") {
                if stripped.contains(":") {
                    // This is not a node key, skip it.
                    continue;
                }
                let zaddr = ZAddr::new_from_encoded(stripped);
                match IpAddr::try_from(zaddr) {
                    Ok(addr) => addrs.push(addr),
                    Err(e) => {
                        return Err(StoreError::InvalidData(format!(
                            "failed to parse node address '{}' as IpAddr: {}",
                            stripped, e
                        )));
                    }
                }
            }
        }
        Ok(addrs)
    }
}

impl Node {
    /// Create a Node object from a node Actor. Returns errors if the actor
    /// is not setup correctly to be a node.
    pub fn new_from_node_actor(actor: &Actor) -> Result<Self, StoreError> {
        if !actor.is_node() {
            return Err(StoreError::InvalidData(
                "attempt to create Node from non-node actor".into(),
            ));
        }
        let cn = match actor.get_cn() {
            Some(c) => c.to_string(),
            None => {
                return Err(StoreError::MissingRequired("node actor missing CN".into()));
            }
        };
        let zpr_addr = match actor.get_zpr_addr() {
            Some(addr) => addr.clone(),
            None => {
                return Err(StoreError::MissingRequired(
                    "node actor missing ZPR address".into(),
                ));
            }
        };
        let substrate_addr = match actor.get_attribute(key::SUBSTRATE_ADDR) {
            Some(addr) => Some(
                addr.get_single_value()
                    .map_err(|e| {
                        StoreError::InvalidData(format!(
                            "failed to get single value for substrate address: {}",
                            e
                        ))
                    })?
                    .parse::<SocketAddr>()
                    .map_err(|e| {
                        StoreError::InvalidData(format!(
                            "failed to parse substrate address attribute as SocketAddr: {}",
                            e
                        ))
                    })?,
            ),
            None => None,
        };
        Ok(Node {
            ctime: SystemTime::now(),
            zpr_addr,
            cn,
            substrate_addr,
        })
    }
}

fn node_key_for_node(addr: &IpAddr) -> String {
    let zaddr = ZAddr::from(addr);
    format!("node:{zaddr}")
}

fn lastseen_key_for_node(addr: &IpAddr) -> String {
    let zaddr = ZAddr::from(addr);
    format!("node:{zaddr}:lastseen")
}

fn vss_key_for_node(addr: &IpAddr) -> String {
    let zaddr = ZAddr::from(addr);
    format!("node:{zaddr}:vss")
}

fn connections_key_for_node(addr: &IpAddr) -> String {
    let zaddr = ZAddr::from(addr);
    format!("node:{zaddr}:connections")
}

fn todo_vinstall_key_for_node(addr: &IpAddr) -> String {
    let zaddr = ZAddr::from(addr);
    format!("node:{zaddr}:todo:vinstall")
}

fn todo_vrevoke_key_for_node(addr: &IpAddr) -> String {
    let zaddr = ZAddr::from(addr);
    format!("node:{zaddr}:todo:vrevoke")
}

fn todo_crevoke_key_for_node(addr: &IpAddr) -> String {
    let zaddr = ZAddr::from(addr);
    format!("node:{zaddr}:todo:crevoke")
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::db::DbConnection;
    use crate::db::db_fake::FakeDb;
    use crate::test_helpers::make_actor;
    use libeval::attribute::{ROLE_ADAPTER, ROLE_NODE};
    use std::time::Duration;

    fn make_node() -> Node {
        Node {
            ctime: SystemTime::UNIX_EPOCH,
            zpr_addr: "fd5a:5052::1".parse().unwrap(),
            cn: "node-1".to_string(),
            substrate_addr: Some("[fd5a:5052::100]:1234".parse().unwrap()),
        }
    }

    #[test]
    fn test_new_from_node_actor_success() {
        let actor = make_actor(
            &[
                (key::ROLE, ROLE_NODE),
                (key::CN, "node-1"),
                (key::ZPR_ADDR, "fd5a:5052::1"),
                (key::SUBSTRATE_ADDR, "[fd5a:5052::100]:1234"),
            ],
            Duration::from_secs(3600),
        );
        let node = Node::new_from_node_actor(&actor).unwrap();
        assert_eq!(node.cn, "node-1");
        assert_eq!(node.zpr_addr, "fd5a:5052::1".parse::<IpAddr>().unwrap());
        assert_eq!(
            node.substrate_addr,
            Some("[fd5a:5052::100]:1234".parse::<SocketAddr>().unwrap())
        );
    }

    #[test]
    fn test_new_from_node_actor_non_node_role() {
        let actor = make_actor(
            &[
                (key::ROLE, ROLE_ADAPTER),
                (key::CN, "node-1"),
                (key::ZPR_ADDR, "fd5a:5052::1"),
                (key::SUBSTRATE_ADDR, "[fd5a:5052::100]:1234"),
            ],
            Duration::from_secs(3600),
        );
        let err = Node::new_from_node_actor(&actor).unwrap_err();
        match err {
            StoreError::InvalidData(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_new_from_node_actor_missing_cn() {
        let actor = make_actor(
            &[
                (key::ROLE, ROLE_NODE),
                (key::ZPR_ADDR, "fd5a:5052::1"),
                (key::SUBSTRATE_ADDR, "[fd5a:5052::100]:1234"),
            ],
            Duration::from_secs(3600),
        );

        let err = Node::new_from_node_actor(&actor).unwrap_err();
        match err {
            StoreError::MissingRequired(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_new_from_node_actor_missing_zpr_addr() {
        let actor = make_actor(
            &[
                (key::ROLE, ROLE_NODE),
                (key::CN, "node-1"),
                (key::SUBSTRATE_ADDR, "[fd5a:5052::100]:1234"),
            ],
            Duration::from_secs(3600),
        );

        let err = Node::new_from_node_actor(&actor).unwrap_err();
        match err {
            StoreError::MissingRequired(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    /// A node with no substrate address claim (no policy address and no observation, as
    /// for the relay) is a valid node with none (zl-zipline#264).
    #[test]
    fn test_new_from_node_actor_missing_substrate_addr() {
        let actor = make_actor(
            &[
                (key::ROLE, ROLE_NODE),
                (key::CN, "node-1"),
                (key::ZPR_ADDR, "fd5a:5052::1"),
            ],
            Duration::from_secs(3600),
        );

        let node = Node::new_from_node_actor(&actor).unwrap();
        assert_eq!(node.substrate_addr, None);
    }

    /// A node with no substrate address stores and loads as one.
    #[tokio::test]
    async fn test_node_repo_round_trips_a_node_without_substrate_addr() {
        let db = Arc::new(FakeDb::new());
        let repo = NodeRepo::new(db.clone());
        let node = Node {
            substrate_addr: None,
            ..make_node()
        };
        repo.add_node(&node).await.unwrap();
        let stored = db
            .get(&node_key_for_node(&node.zpr_addr))
            .await
            .unwrap()
            .unwrap();
        let parsed: Node = serde_json::from_str(&stored).unwrap();
        assert_eq!(parsed.substrate_addr, None);
    }

    #[test]
    fn test_new_from_node_actor_invalid_substrate_addr() {
        let actor = make_actor(
            &[
                (key::ROLE, ROLE_NODE),
                (key::CN, "node-1"),
                (key::ZPR_ADDR, "fd5a:5052::1"),
                (key::SUBSTRATE_ADDR, "not-a-socket-addr"),
            ],
            Duration::from_secs(3600),
        );

        let err = Node::new_from_node_actor(&actor).unwrap_err();
        match err {
            StoreError::InvalidData(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_node_repo_add_and_set_vss() {
        let db = Arc::new(FakeDb::new());
        let repo = NodeRepo::new(db.clone());
        let node = make_node();
        let vss_addr: SocketAddr = "[fd5a:5052::200]:8080".parse().unwrap();

        repo.add_node(&node).await.unwrap();
        repo.set_node_vss(&node.zpr_addr, &vss_addr).await.unwrap();

        let stored_node = db
            .get(&node_key_for_node(&node.zpr_addr))
            .await
            .unwrap()
            .unwrap();
        let parsed_node: Node = serde_json::from_str(&stored_node).unwrap();
        assert_eq!(parsed_node.cn, node.cn);
        assert_eq!(parsed_node.zpr_addr, node.zpr_addr);
        assert_eq!(parsed_node.substrate_addr, node.substrate_addr);

        let stored_vss = db
            .get(&vss_key_for_node(&node.zpr_addr))
            .await
            .unwrap()
            .unwrap();
        let parsed_vss: SAWrapper = serde_json::from_str(&stored_vss).unwrap();
        assert_eq!(parsed_vss.vss_addr, vss_addr);
    }

    #[tokio::test]
    async fn test_node_repo_set_vss_missing_node() {
        let db = Arc::new(FakeDb::new());
        let repo = NodeRepo::new(db);
        let vss_addr: SocketAddr = "[fd5a:5052::200]:8080".parse().unwrap();
        let node_addr: IpAddr = "fd5a:5052::2".parse().unwrap();

        let err = repo.set_node_vss(&node_addr, &vss_addr).await.unwrap_err();
        match err {
            StoreError::NotFound(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_node_repo_connected_adapters_roundtrip() {
        let db = Arc::new(FakeDb::new());
        let repo = NodeRepo::new(db);
        let node_addr: IpAddr = "fd5a:5052::3".parse().unwrap();
        let adapter_a: IpAddr = "fd5a:5052::10".parse().unwrap();
        let adapter_b: IpAddr = "fd5a:5052::11".parse().unwrap();

        repo.add_connected_adater(&node_addr, &adapter_a)
            .await
            .unwrap();
        repo.add_connected_adater(&node_addr, &adapter_b)
            .await
            .unwrap();

        let mut adapters = repo.get_connected_adapters(&node_addr).await.unwrap();
        adapters.sort();
        assert_eq!(adapters, vec![adapter_a, adapter_b]);
    }

    #[tokio::test]
    async fn test_node_repo_remove_node_clears_keys() {
        let db = Arc::new(FakeDb::new());
        let repo = NodeRepo::new(db.clone());
        let node = make_node();
        let vss_addr: SocketAddr = "[fd5a:5052::200]:8080".parse().unwrap();

        repo.add_node(&node).await.unwrap();
        repo.set_node_vss(&node.zpr_addr, &vss_addr).await.unwrap();
        repo.add_connected_adater(&node.zpr_addr, &"fd5a:5052::20".parse().unwrap())
            .await
            .unwrap();

        repo.remove_node(&node.zpr_addr).await.unwrap();

        let keys = vec![
            node_key_for_node(&node.zpr_addr),
            vss_key_for_node(&node.zpr_addr),
            connections_key_for_node(&node.zpr_addr),
            todo_vinstall_key_for_node(&node.zpr_addr),
            todo_vrevoke_key_for_node(&node.zpr_addr),
            todo_crevoke_key_for_node(&node.zpr_addr),
        ];
        for key in keys {
            let exists = db.exists(&key).await.unwrap();
            assert!(!exists, "expected key to be deleted: {}", key);
        }
    }

    #[tokio::test]
    async fn test_list_node_addrs_filters_non_node_keys() {
        let db = Arc::new(FakeDb::new());
        let repo = NodeRepo::new(db.clone());

        let node_a = Node {
            ctime: SystemTime::UNIX_EPOCH,
            zpr_addr: "fd5a:5052::10".parse().unwrap(),
            cn: "node-a".to_string(),
            substrate_addr: Some("[fd5a:5052::100]:1234".parse().unwrap()),
        };
        let node_b = Node {
            ctime: SystemTime::UNIX_EPOCH,
            zpr_addr: "fd5a:5052::11".parse().unwrap(),
            cn: "node-b".to_string(),
            substrate_addr: Some("[fd5a:5052::101]:1234".parse().unwrap()),
        };

        repo.add_node(&node_a).await.unwrap();
        repo.add_node(&node_b).await.unwrap();
        repo.add_connected_adater(&node_a.zpr_addr, &"fd5a:5052::20".parse().unwrap())
            .await
            .unwrap();
        repo.set_node_vss(&node_b.zpr_addr, &"[fd5a:5052::200]:8080".parse().unwrap())
            .await
            .unwrap();

        let mut addrs = repo.list_node_addrs().await.unwrap();
        addrs.sort();

        assert_eq!(addrs, vec![node_a.zpr_addr, node_b.zpr_addr]);
    }

    #[tokio::test]
    async fn test_list_node_addrs_errors_on_invalid_key() {
        let db = Arc::new(FakeDb::new());
        let repo = NodeRepo::new(db.clone());

        db.set("node:bad-zaddr", "junk").await.unwrap();

        let err = repo.list_node_addrs().await.unwrap_err();
        match err {
            StoreError::InvalidData(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_get_last_seen_time_none_before_update() {
        // Checks that get_last_seen_time returns None if there is no timestamp
        let db = Arc::new(FakeDb::new());
        let repo = NodeRepo::new(db);
        let node_addr: IpAddr = "fd5a:5052::10".parse().unwrap();

        let result = repo.get_last_seen_time(&node_addr).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_last_seen_time_exact_value() {
        // Insert a time into the db and ensure get_last_seen time gets correct time
        let db = Arc::new(FakeDb::new());
        let repo = NodeRepo::new(db.clone());
        let node_addr: IpAddr = "fd5a:5052::64".parse().unwrap();

        db.set(
            &lastseen_key_for_node(&node_addr),
            "2024-01-15T10:30:00+00:00",
        )
        .await
        .unwrap();

        let expected = SystemTime::from(
            chrono::DateTime::parse_from_rfc3339("2024-01-15T10:30:00+00:00").unwrap(),
        );
        let result = repo.get_last_seen_time(&node_addr).await.unwrap().unwrap();
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_get_last_seen_time_after_update() {
        // Checks that when we update the db between two known times, last seen time is between those two times
        let db = Arc::new(FakeDb::new());
        let repo = NodeRepo::new(db);
        let node_addr: IpAddr = "fd5a:5052::10".parse().unwrap();

        let before = SystemTime::now();
        repo.update_last_seen_time(&node_addr).await.unwrap();
        let after = SystemTime::now();

        let last_seen = repo.get_last_seen_time(&node_addr).await.unwrap().unwrap();
        assert!(last_seen >= before && last_seen <= after);
    }

    #[tokio::test]
    async fn test_get_last_seen_time_invalid_data() {
        // Returns an error when the stored timestamp is malformed.
        let db = Arc::new(FakeDb::new());
        let repo = NodeRepo::new(db.clone());
        let node_addr: IpAddr = "fd5a:5052::10".parse().unwrap();

        db.set(&lastseen_key_for_node(&node_addr), "not-a-timestamp")
            .await
            .unwrap();

        let err = repo.get_last_seen_time(&node_addr).await.unwrap_err();
        match err {
            StoreError::InvalidData(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }
}

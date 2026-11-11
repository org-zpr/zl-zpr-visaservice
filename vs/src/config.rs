//! Structs that map to the TOML configuration file for the visa service.

use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::ServiceError;

pub const VS_CN: &str = "vs.zpr";

pub const DEFAULT_API_KEYS_FILE: &str = "vs_keys.toml";

pub const ADAPTER_BASE_V6NET: Ipv6Net =
    Ipv6Net::new_assert(Ipv6Addr::new(0xfd5a, 0x5052, 0xadda, 1, 0, 0, 0, 0), 64);
pub const NODE_BASE_V6NET: Ipv6Net =
    Ipv6Net::new_assert(Ipv6Addr::new(0xfd5a, 0x5052, 0x90de, 1, 0, 0, 0, 0), 64);

pub const ADAPTER_BASE_V4NET: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(10, 128, 0, 0), 22);
pub const NODE_BASE_V4NET: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(10, 192, 0, 0), 22);

pub const MAX_VISA_REQUEST_WORKERS: usize = 1024;
pub const VISA_REQUEST_QUEUE_DEPTH: usize = 1024;
pub const EVENT_QUEUE_DEPTH: usize = 1024;

// We only load policy files built by exactly this minor version (and any
// patch >= the minimum): pre-1.0, an advanced compiler minor means "probably
// won't work with this visa service", so vs rejects it (zipline#114). This
// constant therefore moves in lockstep with zplc's minor on every zplc minor
// bump.
pub const POLICY_MIN_COMPILER_MAJOR: u32 = 0;
pub const POLICY_MIN_COMPILER_MINOR: u32 = 20;
pub const POLICY_MIN_COMPILER_PATCH: u32 = 0;

/// Retry hint (seconds) sent with `temporarilyUnavailable` when an OIDC
/// provider has no signing keys at all yet (no seed, no successful fetch).
pub const OIDC_NO_KEYS_RETRY_SECS: u32 = 30;

/// Minimum policy compiler version this build will load.

pub const POLICY_MIN_VERSION: libeval::pio::Version = libeval::pio::Version(
    POLICY_MIN_COMPILER_MAJOR,
    POLICY_MIN_COMPILER_MINOR,
    POLICY_MIN_COMPILER_PATCH,
);

/// Default VSAPI port - must be in sync with compiler since it adds policy for that.
pub const VSAPI_PORT: u16 = 5002;

/// Default VS admin HTTPS port - must be in sync with compiler since it adds policy for that.
pub const ADMIN_HTTPS_PORT: u16 = 8182;

/// Initial visa ID to use when creating visas - must be in sync with the nodes since they create
/// initial "hardcoded" visas using IDs below this. This value is only set if we do not have
/// state in the database yet.
pub const INITIAL_VISA_ID: u64 = 1000;

pub const VALKEY_URI: &str = "redis://127.0.0.1:6379";

/// Every THIS often we re-acquire the DB lock.
pub const VALKEY_LOCK_REFRESH_SECS: Duration = Duration::from_secs(30);

/// We set the DB lock to expire after THIS long.
pub const VALKEY_LOCK_TIMEOUT: Duration = Duration::from_secs(90);

/// On renewal failure, retry at this faster cadence.
pub const VALKEY_LOCK_RETRY_SECS: Duration = Duration::from_secs(5);

/// Default VS ZPR address - must be in sync with compiler.
pub const VS_ZPR_ADDR: Ipv6Addr = Ipv6Addr::new(
    0xfd5a, 0x5052, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, // fd5a:5052::1
);

/// Maximum allowed clock skew allowed during node authentication, in seconds.
pub const MAX_CLOCK_SKEW_SECS: u64 = 180;

/// Lifetime of a visa-service-minted OIDC login nonce (`getLoginNonce`,
/// zl-zipline#232), in seconds. Long enough for an interactive browser login.
pub const LOGIN_NONCE_TTL_SECS: u64 = 300;

/// Maximum number of unexpired outstanding login nonces one node actor session
/// may hold; minting past it is refused with `quotaExceeded` (zl-zipline#232).
pub const LOGIN_NONCE_MAX_PER_ACTOR: usize = 4;

pub const MAX_VISA_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours

/// A visa must be valid for at least this long to be worth issuing. Below this the node
/// install (see [VSS_START_DELAY]) plus the round trip eats the whole lifetime, and under
/// one second the visa store's seconds-granularity TTL truncates to zero and drops it.
pub const MIN_VISA_LIFETIME: Duration = Duration::from_secs(30);

pub const DEFAULT_AUTH_EXPIRATION: Duration = Duration::from_secs(4 * 60 * 60); // 4 hours

/// Expiration used on the visa service's own identity attributes. The VS must not expire its own
/// authentication so this is set far enough out to never be reached.
pub const VS_AUTH_EXPIRATION: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60); // ~100 years

/// When an actor is using an AAA address to do an exchange with an auth
/// service, the credentials it is using last this long.
///
/// TODO: Figure out what we are really ding with AAA addresses. For now setting to
/// the `DEFAULT_AUTH_EXPIRATION` value.
pub const DEFAULT_ANON_AUTH_EXPIRATION: Duration = DEFAULT_AUTH_EXPIRATION;

/// How long to wait after getting the VSS addr from the node and opening a connection back to it.
/// This delay allows time for the node to install the visa before we try to use it.
pub const VSS_START_DELAY: std::time::Duration = std::time::Duration::from_secs(3);

/// VSS worker pings the node VSS API at this interval.
pub const VSS_PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(7);

/// VSS wakes up to check for visas or other housekeeping this often.
pub const VSS_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(800);

/// Number of allowed consecutive VSS ping failures before we drop the node.
pub const VSS_MAX_PING_FAILURES: usize = 3;

/// In cases where we create visas ourselves or if no timeout is specified, use this default.
pub const DEFAULT_VISA_REQ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Max number of visas the node can request at a time
pub const MAX_NUM_VISA_REQUEST: usize = 20;

/// Size of the in-memory recent-denies window kept by the deny log.
pub const DENY_LOG_SIZE: usize = 500;

/// Default for the `reauth_deadline` setting (zipline#123): how long a
/// connected actor has, after a policy install, to re-authenticate under the
/// new policy generation before it is revoked.
pub const DEFAULT_REAUTH_DEADLINE_SECS: u64 = 300;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct VSConfig {
    pub core: CoreSection,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct CoreSection {
    /// The visa service bind address - this is a constant baked into entire ZPR system only override for testing.
    pub vs_addr: Option<IpAddr>,

    /// VSAPI port used by nodes to talk to the visa service VS API.
    /// Must be kept in sync with the compiler.
    pub vsapi_port: Option<u16>,

    /// HTTPS Admin port used to control the visa service.
    /// Must be kept in sync with the compiler.
    pub admin_port: Option<u16>,

    /// TLS Certificate for HTTPS admin service.
    pub admin_cert: PathBuf,

    /// TLS Private Key for HTTPS admin service.
    pub admin_key: PathBuf,

    /// ValKey connect string.
    pub vk_uri: Option<String>,

    /// The identity string used to tie this visa service to the state database.
    /// Overrides any stored identity file and disables the auto-generation of an identity UUID.
    /// If set this must be a non-empty string.
    pub identity: Option<String>,

    /// Path to the API keys file.
    pub api_keys: Option<PathBuf>,

    /// Directory holding the `<service-id>.json` attribute files for `api=file` trusted services.
    pub file_ts_dir: Option<PathBuf>,

    /// Directory holding the `<service-id>.token` bearer-token files for
    /// `api = "zpr-attr/1"` trusted services. The token authenticates the visa
    /// service to the attribute service and deliberately never lives in the
    /// signed policy (docs/ATTRIBUTE_SERVICE.md, *Configuration*). Relative
    /// paths anchor at the config file's directory, like `file_ts_dir`.
    pub ts_secrets_dir: Option<PathBuf>,

    /// Period, in seconds, between JWKS refreshes for `api=oidc` trusted
    /// services. Unset or 0 disables the periodic refresher — the policy
    /// manager warns per provider, and key rotation is then picked up only
    /// by connect-path misses (zipline#19). There is deliberately no
    /// visa-service default: the compiler-emitted `OidcConfig` carries no
    /// refresh interval today, so any period is an explicit operator choice.
    pub oidc_refresh_seconds: Option<u64>,

    /// Seconds a connected actor has, after a policy install, to
    /// re-authenticate under the new policy generation before it is revoked
    /// (zipline#123). Default [DEFAULT_REAUTH_DEADLINE_SECS].
    pub reauth_deadline: Option<u64>,
}

impl Default for VSConfig {
    fn default() -> Self {
        VSConfig {
            core: CoreSection::default(),
        }
    }
}
impl Default for CoreSection {
    fn default() -> Self {
        CoreSection {
            vs_addr: Some(IpAddr::V6(VS_ZPR_ADDR)),
            vsapi_port: Some(VSAPI_PORT),
            admin_port: Some(ADMIN_HTTPS_PORT),
            admin_cert: PathBuf::from("admin-tls-cert.pem"),
            admin_key: PathBuf::from("admin-tls-key.pem"),
            vk_uri: Some(VALKEY_URI.to_string()),
            identity: Some(String::new()),
            api_keys: Some(PathBuf::from(DEFAULT_API_KEYS_FILE)),
            file_ts_dir: Some(PathBuf::from(".")),
            ts_secrets_dir: Some(PathBuf::from(".")),
            oidc_refresh_seconds: None,
            reauth_deadline: Some(DEFAULT_REAUTH_DEADLINE_SECS),
        }
    }
}

impl VSConfig {
    /// Load configuration from a file. Relative paths in the file resolve
    /// relative to the directory containing the file, not the CWD.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ServiceError> {
        let contents = std::fs::read_to_string(path)?;
        let mut cfg: VSConfig = toml::from_str(&contents)?;
        // An empty parent (e.g. plain "vs.toml") means the config sits in the
        // CWD; joining an empty base is a no-op, preserving that behavior.
        if let Some(base) = path.parent() {
            cfg.resolve_paths(base);
        }
        Ok(cfg)
    }

    /// Rebase every relative path setting onto `base` (the config file's
    /// directory). Absolute paths are left untouched.
    fn resolve_paths(&mut self, base: &std::path::Path) {
        // Joining a relative path onto `base` anchors it to the config file's
        // location; `Path::join` replaces the base entirely for absolute paths,
        // so those pass through unchanged.
        fn rebase(base: &std::path::Path, p: &mut PathBuf) {
            *p = base.join(&*p);
        }
        rebase(base, &mut self.core.admin_cert);
        rebase(base, &mut self.core.admin_key);
        if let Some(p) = self.core.api_keys.as_mut() {
            rebase(base, p);
        }
        if let Some(p) = self.core.file_ts_dir.as_mut() {
            rebase(base, p);
        }
        if let Some(p) = self.core.ts_secrets_dir.as_mut() {
            rebase(base, p);
        }
    }

    pub fn get_vs_addr(&self) -> IpAddr {
        self.core.vs_addr.unwrap_or(IpAddr::V6(VS_ZPR_ADDR))
    }
}

// Return the path to the data home directory.
//
// Resolution order follows the XDG Base Directory spec: `$XDG_DATA_HOME` if
// set, otherwise `$HOME/.local/share` (whether or not it exists yet -- the
// caller creates it), otherwise `/var/lib` for processes with no HOME at all
// (e.g. some systemd units). We deliberately never fall back to `/var/run`:
// it is tmpfs, so anything stored there is silently lost on reboot.
pub fn get_data_home() -> PathBuf {
    data_home_from(
        env::var("XDG_DATA_HOME").ok().as_deref(),
        env::var("HOME").ok().as_deref(),
    )
}

// Pure helper behind [get_data_home]: computes the data home directory from
// the given values of `XDG_DATA_HOME` and `HOME`. Split out so the resolution
// logic is unit-testable without mutating process environment variables.
fn data_home_from(xdg_data_home: Option<&str>, home: Option<&str>) -> PathBuf {
    // The XDG Base Directory spec requires these variables to hold absolute
    // paths and says invalid (relative) values must be ignored. Honouring a
    // relative value would tie the identity location to the process's working
    // directory, so a restart from elsewhere would mint a new identity.
    let mut dh = match xdg_data_home {
        Some(val) if !val.trim().is_empty() && Path::new(val).is_absolute() => PathBuf::from(val),
        _ => match home {
            Some(val) if !val.trim().is_empty() => {
                let mut pb = PathBuf::from(val);
                pb.push(".local/share");
                pb
            }
            // No HOME: persistent variable state belongs in /var/lib (FHS).
            _ => PathBuf::from("/var/lib"),
        },
    };
    dh.push("zpr");
    dh
}

#[cfg(test)]
mod test {
    use super::*;

    // XDG_DATA_HOME, when set and non-empty, wins outright.
    #[test]
    fn test_data_home_prefers_xdg_data_home() {
        assert_eq!(
            data_home_from(Some("/custom/data"), Some("/home/u")),
            PathBuf::from("/custom/data/zpr")
        );
    }

    // Without XDG_DATA_HOME, HOME/.local/share is used even if it does not
    // exist yet -- the caller is responsible for creating it (XDG spec).
    #[test]
    fn test_data_home_uses_home_local_share_without_existence_gate() {
        let nonexistent = "/definitely/not/a/real/home";
        assert_eq!(
            data_home_from(None, Some(nonexistent)),
            PathBuf::from(nonexistent).join(".local/share/zpr")
        );
        // Empty XDG_DATA_HOME is treated as unset.
        assert_eq!(
            data_home_from(Some(""), Some(nonexistent)),
            PathBuf::from(nonexistent).join(".local/share/zpr")
        );
    }

    // A relative XDG_DATA_HOME violates the XDG spec and must be ignored,
    // falling through to the HOME-based (or /var/lib) resolution.
    #[test]
    fn test_data_home_ignores_relative_xdg_data_home() {
        assert_eq!(
            data_home_from(Some(".data"), Some("/home/u")),
            PathBuf::from("/home/u/.local/share/zpr")
        );
        assert_eq!(
            data_home_from(Some("relative/path"), None),
            PathBuf::from("/var/lib/zpr")
        );
    }

    // With neither variable set, fall back to /var/lib (persistent, per FHS),
    // never /var/run (tmpfs, wiped on reboot).
    #[test]
    fn test_data_home_falls_back_to_var_lib() {
        assert_eq!(data_home_from(None, None), PathBuf::from("/var/lib/zpr"));
        assert_eq!(
            data_home_from(Some(""), Some("")),
            PathBuf::from("/var/lib/zpr")
        );
    }

    #[test]
    fn test_override_one_field_deserialize() {
        let cfg: VSConfig = toml::from_str(
            r#"
        [core]
        vsapi_port = 9999
        "#,
        )
        .unwrap();
        assert_eq!(cfg.core.vk_uri, Some(VALKEY_URI.to_string()));
        assert_eq!(cfg.core.vsapi_port, Some(9999));
    }

    // Write `contents` into a temp dir as vs.toml and load it via from_file,
    // returning the parsed config and the temp dir (kept alive by the caller).
    fn load_from_temp_dir(contents: &str) -> (VSConfig, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("vs.toml");
        std::fs::write(&cfg_path, contents).unwrap();
        let cfg = VSConfig::from_file(&cfg_path).unwrap();
        (cfg, dir)
    }

    // Relative path fields in the config file must resolve relative to the
    // config file's directory, not the process's working directory.
    #[test]
    fn test_relative_paths_resolve_relative_to_config_file() {
        let (cfg, dir) = load_from_temp_dir(
            r#"
        [core]
        admin_cert = "certs/cert.pem"
        admin_key = "certs/key.pem"
        api_keys = "keys.toml"
        file_ts_dir = "include"
        ts_secrets_dir = "secrets"
        "#,
        );
        let base = dir.path();
        assert_eq!(cfg.core.admin_cert, base.join("certs/cert.pem"));
        assert_eq!(cfg.core.admin_key, base.join("certs/key.pem"));
        assert_eq!(cfg.core.api_keys, Some(base.join("keys.toml")));
        assert_eq!(cfg.core.file_ts_dir, Some(base.join("include")));
        assert_eq!(cfg.core.ts_secrets_dir, Some(base.join("secrets")));
    }

    // Absolute path fields must be left exactly as written; anchoring only
    // applies to relative paths.
    #[test]
    fn test_absolute_paths_are_untouched() {
        let (cfg, _dir) = load_from_temp_dir(
            r#"
        [core]
        admin_cert = "/etc/zpr/cert.pem"
        api_keys = "/etc/zpr/keys.toml"
        ts_secrets_dir = "/etc/zpr/secrets"
        "#,
        );
        assert_eq!(cfg.core.admin_cert, PathBuf::from("/etc/zpr/cert.pem"));
        assert_eq!(cfg.core.api_keys, Some(PathBuf::from("/etc/zpr/keys.toml")));
        assert_eq!(
            cfg.core.ts_secrets_dir,
            Some(PathBuf::from("/etc/zpr/secrets"))
        );
    }

    #[test]
    fn test_unset_path_fields_default_relative_to_config_dir() {
        // Fields absent from the file take the struct defaults, which are
        // relative and therefore also anchor to the config file's directory.
        let (cfg, dir) = load_from_temp_dir(
            r#"
        [core]
        vsapi_port = 9999
        "#,
        );
        let base = dir.path();
        assert_eq!(cfg.core.admin_cert, base.join("admin-tls-cert.pem"));
        assert_eq!(cfg.core.admin_key, base.join("admin-tls-key.pem"));
        assert_eq!(cfg.core.api_keys, Some(base.join(DEFAULT_API_KEYS_FILE)));
        assert_eq!(cfg.core.file_ts_dir, Some(base.join(".")));
        assert_eq!(cfg.core.ts_secrets_dir, Some(base.join(".")));
    }

    #[test]
    fn test_bare_filename_config_path_keeps_cwd_relative_paths() {
        // A config path with no directory component ("vs.toml") has an empty
        // parent; rebasing onto it must leave relative paths unchanged.
        let mut cfg: VSConfig = toml::from_str(
            r#"
        [core]
        admin_cert = "cert.pem"
        "#,
        )
        .unwrap();
        cfg.resolve_paths(std::path::Path::new("vs.toml").parent().unwrap());
        assert_eq!(cfg.core.admin_cert, PathBuf::from("cert.pem"));
    }

    // The shipped POLICY_MIN_VERSION must accept what the current zplc emits.
    // check_version matches the minor version exactly (deliberate, zipline#114:
    // an advanced minor means "probably won't work with this vs", so vs rejects
    // it), which makes this constant the single thing that has to move in
    // lockstep with the compiler's version — this test is what fails when zplc
    // advances its minor and the constant is left behind.
    #[test]
    fn test_policy_min_version_accepts_current_compiler_output() {
        // Minimal valid inner policy, same shape as test_helpers builders emit.
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy = msg.init_root::<zpr::policy::v1::policy::Builder>();
            policy.set_created("2026-01-01T00:00:00Z");
            policy.set_version(1);
            policy.set_metadata("");
        }
        let mut inner = Vec::new();
        capnp::serialize::write_message(&mut inner, &msg).unwrap();

        // zplc at tip is 0.20.0: its containers must load.
        let current = crate::test_helpers::make_container_bytes(0, 20, 0, &inner);
        let loaded = libeval::pio::load_policy_from_container(
            &bytes::Bytes::from(current),
            &POLICY_MIN_VERSION,
        );
        assert!(
            loaded.is_ok(),
            "a 0.20.0-compiled policy container must load against POLICY_MIN_VERSION {}: {:?}",
            POLICY_MIN_VERSION,
            loaded.err()
        );

        // The previous minor must be rejected — exact-minor matching.
        let previous = crate::test_helpers::make_container_bytes(0, 19, 3, &inner);
        assert!(
            libeval::pio::load_policy_from_container(
                &bytes::Bytes::from(previous),
                &POLICY_MIN_VERSION
            )
            .is_err(),
            "a 0.19.x-compiled policy container must be rejected by POLICY_MIN_VERSION {} (exact-minor match)",
            POLICY_MIN_VERSION
        );
    }
}

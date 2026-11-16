//! zl-zipline#266: `vs` exits with a non-zero status, and says why, when a
//! listener cannot bind `vs_addr`. Before the fix the VS-API task logged the
//! error and ended while the rest of the service kept running, so a
//! misconfigured `vs_addr` gave a visa service with no VS-API.
//!
//! The bind runs before ValKey: the config points `vk_uri` at a closed port,
//! so a `vs` that reached ValKey first would fail there instead, with a
//! different message, and the test would catch it.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long `vs` gets to exit. The bind fails at once; ValKey is never
/// contacted, so nothing should wait on a connect timeout.
const EXIT_DEADLINE: Duration = Duration::from_secs(10);

/// A TCP port on 127.0.0.1 that nothing listens on: bind an ephemeral port
/// and release it.
fn closed_local_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().port()
}

/// Run `vs -c <dir>/vs.toml` with `vs_addr` set to an address that is on no
/// local interface (2001:db8::/32 is the RFC 3849 documentation prefix), and
/// return the exit status and the combined stdout and stderr.
fn run_vs_with_non_local_vs_addr() -> (std::process::ExitStatus, String) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("vs.toml");
    std::fs::write(
        &cfg,
        format!(
            "[core]\n\
             vs_addr = \"2001:db8::1\"\n\
             vk_uri = \"redis://127.0.0.1:{}\"\n\
             identity = \"listener-bind-test\"\n",
            closed_local_port()
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_vs"))
        .arg("-c")
        .arg(&cfg)
        .current_dir(dir.path())
        .env("XDG_DATA_HOME", dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run vs");

    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > EXIT_DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            let mut out = String::new();
            let _ = child.stdout.take().unwrap().read_to_string(&mut out);
            let _ = child.stderr.take().unwrap().read_to_string(&mut out);
            panic!("vs did not exit within {EXIT_DEADLINE:?}; output:\n{out}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    (status, out)
}

#[test]
fn vs_exits_when_vs_addr_is_not_local() {
    let (status, out) = run_vs_with_non_local_vs_addr();
    assert_eq!(
        status.code(),
        Some(1),
        "vs must exit with status 1 (ExitCode::FAILURE), got {status:?}; output:\n{out}"
    );
    assert!(
        out.contains("cannot bind VS-API listener on [2001:db8::1]:"),
        "the log must name the listener and the address; output:\n{out}"
    );
    assert!(
        out.contains("vs_addr must be an address on a local interface"),
        "the log must name the remedy; output:\n{out}"
    );
    assert!(
        !out.contains("connecting to ValKey") && !out.contains("redis"),
        "vs must fail before it contacts ValKey; output:\n{out}"
    );
}

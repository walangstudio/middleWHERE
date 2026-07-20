//! Control-channel wire protocol.
//!
//! The unprivileged CLI sends config-mutation and read requests over a
//! length-prefixed CBOR frame stream; the privileged daemon applies them and
//! replies. IO-generic (`std::io::Read`/`Write`) so the synchronous CLI and the
//! async daemon share one codec — the daemon does its framing off a
//! `spawn_blocking` / buffered adapter, mw-core stays tokio-free.
//!
//! Framing: a 4-byte big-endian length prefix followed by that many CBOR bytes.
//! Frames larger than [`MAX_FRAME`] are refused on both encode and decode, so a
//! hostile declared length can never drive an unbounded allocation.

use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::config::{Config, EngineKind, HostKeyFingerprint, Policy};
use crate::mutate::{BastionAuthInput, NewEnvOutput, PolicyTarget};
use crate::secret::SecretStr;

/// Bumped whenever the wire format changes incompatibly. The CLI sends it in
/// [`Request::Hello`]; the daemon rejects a mismatch before doing any work.
pub const PROTOCOL_VERSION: u16 = 1;

/// Hard cap on a single frame's CBOR body. Bounds both the CLI's outbound
/// encode and the daemon's inbound decode allocation.
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

// ---------------------------------------------------------------------------
// request payload DTOs — owned mirrors of the CLI's `ops`-level inputs, with
// secrets already resolved (no key-file paths or stdin flags cross the wire).
// ---------------------------------------------------------------------------

/// Mirrors `mwsqlctl::ops::BastionInput`, with the auth secret resolved and the
/// fingerprint parsed on the CLI side.
#[derive(Debug, Serialize, Deserialize)]
pub struct BastionInputDto {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub ssh_user: String,
    pub auth: BastionAuthInput,
    pub fingerprint: Option<HostKeyFingerprint>,
}

/// Mirrors `mwsqlctl::ops::EnvInput`. `backend_port` stays optional so the
/// daemon applies the engine's default port, matching the CLI.
#[derive(Debug, Serialize, Deserialize)]
pub struct EnvInputDto {
    pub name: String,
    pub backend_host: String,
    pub backend_port: Option<u16>,
    pub engine: EngineKind,
    pub database: Option<String>,
    pub bastion: Option<String>,
    pub credential: String,
    pub policy: Policy,
    pub listen_port: Option<u16>,
    pub max_pool: Option<u32>,
}

/// A backend credential to add: name + backend user + resolved password.
#[derive(Debug, Serialize, Deserialize)]
pub struct CredInputDto {
    pub name: String,
    pub backend_user: String,
    pub password: SecretStr,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// Version preamble; the daemon checks this before anything else.
    Hello {
        version: u16,
    },
    // --- mutations ---
    AddBastion(BastionInputDto),
    RmBastion {
        name: String,
    },
    SetFingerprint {
        bastion: String,
        fingerprint: HostKeyFingerprint,
    },
    AddCred(CredInputDto),
    RotateCred {
        name: String,
        password: SecretStr,
    },
    RmCred {
        name: String,
    },
    AddEnv(EnvInputDto),
    RmEnv {
        name: String,
    },
    Grant {
        env: String,
    },
    SetPolicy {
        env: String,
        target: PolicyTarget,
        confirm_unsafe: bool,
    },
    /// A config fragment the CLI parsed from a legacy `.env`+`secrets/` source;
    /// the daemon merges it. Boxed to keep the enum's other variants small.
    Import(Box<Config>),
    // --- reads ---
    ListBastions,
    ListCreds,
    ListEnvs,
    AuditTail {
        n: usize,
    },
    Probe {
        env: Option<String>,
        all: bool,
    },
}

/// The client token + connection facts returned by `AddEnv`/`Grant`. Mirrors
/// [`crate::mutate::NewEnvOutput`].
#[derive(Debug, Serialize, Deserialize)]
pub struct NewEnvOutputDto {
    pub token: SecretStr,
    pub listen_port: u16,
    pub engine: EngineKind,
    pub database: Option<String>,
    /// Optional advisory the CLI should surface alongside the token. `None` on a
    /// clean success; set when the env was persisted (token minted) but its live
    /// bind failed, so the operator learns the env needs a restart to go live
    /// instead of silently getting a token for a not-yet-serving env.
    #[serde(default)]
    pub note: Option<String>,
}

impl From<NewEnvOutput> for NewEnvOutputDto {
    fn from(o: NewEnvOutput) -> Self {
        Self {
            token: o.token,
            listen_port: o.listen_port,
            engine: o.engine,
            database: o.database,
            note: None,
        }
    }
}

/// Mirrors `mwsqld`'s `EnvProbeResult`: connectivity outcome for one env.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProbeResultDto {
    pub env: String,
    pub ok: bool,
    pub supported: bool,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Token(NewEnvOutputDto),
    Rows(Vec<String>),
    AuditLines(Vec<String>),
    ProbeResults(Vec<ProbeResultDto>),
    /// The request was well-formed but refused by authorization/policy.
    Denied(String),
    /// The mutation or read failed; carries a human-readable message.
    Error(String),
}

/// Platform runtime dir the installer provisions for the control socket: systemd
/// `RuntimeDirectory` at `/run/middlewhere` on Linux, `/var/run/middlewhere` on
/// macOS (stock macOS has no `/run`). `None` on a platform without a
/// conventional runtime dir. Single source of truth shared by the daemon (which
/// binds the socket there) and the CLI (which connects to it); pure over the OS
/// name (`std::env::consts::OS`) so every branch is testable.
pub fn runtime_dir_for(os: &str) -> Option<std::path::PathBuf> {
    match os {
        "linux" => Some(std::path::PathBuf::from("/run/middlewhere")),
        "macos" => Some(std::path::PathBuf::from("/var/run/middlewhere")),
        _ => None,
    }
}

/// Encode `msg` as a length-prefixed CBOR frame and flush it. Errors (rather
/// than truncating) if the body would exceed [`MAX_FRAME`].
pub fn write_frame<W: std::io::Write, T: Serialize>(w: &mut W, msg: &T) -> Result<()> {
    let mut body = Vec::new();
    ciborium::ser::into_writer(msg, &mut body).context("cbor-encode frame")?;
    if body.len() > MAX_FRAME {
        bail!("frame body {} exceeds MAX_FRAME {}", body.len(), MAX_FRAME);
    }
    // Cast is safe: MAX_FRAME (8 MiB) fits in u32.
    let len = body.len() as u32;
    w.write_all(&len.to_be_bytes())
        .context("write frame length")?;
    w.write_all(&body).context("write frame body")?;
    w.flush().context("flush frame")?;
    Ok(())
}

/// Read one length-prefixed CBOR frame. Rejects a declared length over
/// [`MAX_FRAME`] before allocating, and surfaces a truncated body as an error.
pub fn read_frame<R: std::io::Read, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).context("read frame length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        bail!("frame length {len} exceeds MAX_FRAME {MAX_FRAME}");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).context("read frame body")?;
    ciborium::de::from_reader(body.as_slice()).context("cbor-decode frame")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretBytes;

    fn roundtrip<T: Serialize + DeserializeOwned>(msg: &T) -> T {
        let mut buf = Vec::new();
        write_frame(&mut buf, msg).unwrap();
        read_frame(&mut buf.as_slice()).unwrap()
    }

    fn sample_requests() -> Vec<Request> {
        vec![
            Request::Hello {
                version: PROTOCOL_VERSION,
            },
            Request::AddBastion(BastionInputDto {
                name: "b".into(),
                host: "h".into(),
                port: 22,
                ssh_user: "u".into(),
                auth: BastionAuthInput::Key {
                    pem: SecretBytes::new(b"PEMBYTES".to_vec()),
                    passphrase: Some(SecretStr::new("pp")),
                },
                fingerprint: Some(HostKeyFingerprint {
                    algo: "ssh-ed25519".into(),
                    sha256_b64: "AAAA".into(),
                }),
            }),
            Request::RmBastion { name: "b".into() },
            Request::SetFingerprint {
                bastion: "b".into(),
                fingerprint: HostKeyFingerprint {
                    algo: "ssh-rsa".into(),
                    sha256_b64: "BBBB".into(),
                },
            },
            Request::AddCred(CredInputDto {
                name: "c".into(),
                backend_user: "dbuser".into(),
                password: SecretStr::new("secret-pw"),
            }),
            Request::RotateCred {
                name: "c".into(),
                password: SecretStr::new("new-pw"),
            },
            Request::RmCred { name: "c".into() },
            Request::AddEnv(EnvInputDto {
                name: "e".into(),
                backend_host: "db".into(),
                backend_port: None,
                engine: EngineKind::Postgres,
                database: Some("orders".into()),
                bastion: Some("b".into()),
                credential: "c".into(),
                policy: Policy::ReadOnly,
                listen_port: Some(6040),
                max_pool: Some(8),
            }),
            Request::RmEnv { name: "e".into() },
            Request::Grant { env: "e".into() },
            Request::SetPolicy {
                env: "e".into(),
                target: PolicyTarget::ReadWrite,
                confirm_unsafe: true,
            },
            Request::Import(Box::default()),
            Request::ListBastions,
            Request::ListCreds,
            Request::ListEnvs,
            Request::AuditTail { n: 25 },
            Request::Probe {
                env: Some("e".into()),
                all: false,
            },
        ]
    }

    #[test]
    fn every_request_variant_round_trips() {
        for req in sample_requests() {
            let back = roundtrip(&req);
            // Match on both sides to assert the variant + a representative field
            // (secrets compared via expose) survives the codec.
            match (&req, &back) {
                (Request::Hello { version: a }, Request::Hello { version: b }) => assert_eq!(a, b),
                (Request::AddBastion(a), Request::AddBastion(b)) => {
                    assert_eq!(a.name, b.name);
                    assert_eq!(a.port, b.port);
                    match (&a.auth, &b.auth) {
                        (
                            BastionAuthInput::Key {
                                pem: pa,
                                passphrase: sa,
                            },
                            BastionAuthInput::Key {
                                pem: pb,
                                passphrase: sb,
                            },
                        ) => {
                            assert_eq!(pa.expose(), pb.expose());
                            assert_eq!(
                                sa.as_ref().map(|s| s.expose().to_string()),
                                sb.as_ref().map(|s| s.expose().to_string())
                            );
                        }
                        _ => panic!("auth variant changed"),
                    }
                    assert_eq!(a.fingerprint.is_some(), b.fingerprint.is_some());
                }
                (Request::RmBastion { name: a }, Request::RmBastion { name: b }) => {
                    assert_eq!(a, b)
                }
                (
                    Request::SetFingerprint {
                        bastion: a,
                        fingerprint: fa,
                    },
                    Request::SetFingerprint {
                        bastion: b,
                        fingerprint: fb,
                    },
                ) => {
                    assert_eq!(a, b);
                    assert_eq!(fa.sha256_b64, fb.sha256_b64);
                }
                (Request::AddCred(a), Request::AddCred(b)) => {
                    assert_eq!(a.name, b.name);
                    assert_eq!(a.backend_user, b.backend_user);
                    assert_eq!(a.password.expose(), b.password.expose());
                }
                (
                    Request::RotateCred {
                        name: a,
                        password: pa,
                    },
                    Request::RotateCred {
                        name: b,
                        password: pb,
                    },
                ) => {
                    assert_eq!(a, b);
                    assert_eq!(pa.expose(), pb.expose());
                }
                (Request::RmCred { name: a }, Request::RmCred { name: b }) => assert_eq!(a, b),
                (Request::AddEnv(a), Request::AddEnv(b)) => {
                    assert_eq!(a.name, b.name);
                    assert_eq!(a.engine, b.engine);
                    assert_eq!(a.backend_port, b.backend_port);
                    assert_eq!(a.listen_port, b.listen_port);
                    assert_eq!(a.max_pool, b.max_pool);
                    assert_eq!(a.database, b.database);
                }
                (Request::RmEnv { name: a }, Request::RmEnv { name: b }) => assert_eq!(a, b),
                (Request::Grant { env: a }, Request::Grant { env: b }) => assert_eq!(a, b),
                (
                    Request::SetPolicy {
                        env: a,
                        target: ta,
                        confirm_unsafe: ca,
                    },
                    Request::SetPolicy {
                        env: b,
                        target: tb,
                        confirm_unsafe: cb,
                    },
                ) => {
                    assert_eq!(a, b);
                    assert_eq!(ta, tb);
                    assert_eq!(ca, cb);
                }
                (Request::Import(a), Request::Import(b)) => {
                    assert_eq!(a.schema_version, b.schema_version);
                    assert_eq!(a.envs.len(), b.envs.len());
                }
                (Request::ListBastions, Request::ListBastions) => {}
                (Request::ListCreds, Request::ListCreds) => {}
                (Request::ListEnvs, Request::ListEnvs) => {}
                (Request::AuditTail { n: a }, Request::AuditTail { n: b }) => assert_eq!(a, b),
                (Request::Probe { env: a, all: aa }, Request::Probe { env: b, all: ab }) => {
                    assert_eq!(a, b);
                    assert_eq!(aa, ab);
                }
                _ => panic!("request variant changed across round-trip"),
            }
        }
    }

    fn sample_responses() -> Vec<Response> {
        vec![
            Response::Ok,
            Response::Token(NewEnvOutputDto {
                token: SecretStr::new("tok-123"),
                listen_port: 6033,
                engine: EngineKind::MySql,
                database: Some("app".into()),
                note: Some("persisted but not yet live".into()),
            }),
            Response::Rows(vec!["a".into(), "b".into()]),
            Response::AuditLines(vec!["line1".into(), "line2".into()]),
            Response::ProbeResults(vec![ProbeResultDto {
                env: "e".into(),
                ok: true,
                supported: true,
                reason: String::new(),
            }]),
            Response::Denied("peer not root".into()),
            Response::Error("boom".into()),
        ]
    }

    #[test]
    fn every_response_variant_round_trips() {
        for resp in sample_responses() {
            let back = roundtrip(&resp);
            match (&resp, &back) {
                (Response::Ok, Response::Ok) => {}
                (Response::Token(a), Response::Token(b)) => {
                    assert_eq!(a.token.expose(), b.token.expose());
                    assert_eq!(a.listen_port, b.listen_port);
                    assert_eq!(a.engine, b.engine);
                    assert_eq!(a.database, b.database);
                    assert_eq!(a.note, b.note);
                }
                (Response::Rows(a), Response::Rows(b)) => assert_eq!(a, b),
                (Response::AuditLines(a), Response::AuditLines(b)) => assert_eq!(a, b),
                (Response::ProbeResults(a), Response::ProbeResults(b)) => {
                    assert_eq!(a.len(), b.len());
                    assert_eq!(a[0].env, b[0].env);
                    assert_eq!(a[0].ok, b[0].ok);
                    assert_eq!(a[0].supported, b[0].supported);
                }
                (Response::Denied(a), Response::Denied(b)) => assert_eq!(a, b),
                (Response::Error(a), Response::Error(b)) => assert_eq!(a, b),
                _ => panic!("response variant changed across round-trip"),
            }
        }
    }

    #[test]
    fn oversized_declared_length_is_rejected_not_allocated() {
        // A 4-byte prefix declaring MAX_FRAME+1, with no body. read_frame must
        // error on the length check before trying to allocate/read the body.
        let mut framed = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&[0u8; 8]);
        let err = read_frame::<_, Request>(&mut framed.as_slice()).unwrap_err();
        assert!(err.to_string().contains("exceeds MAX_FRAME"), "{err}");
    }

    #[test]
    fn write_frame_refuses_oversized_body() {
        // A payload whose CBOR body exceeds MAX_FRAME must error, not truncate.
        let big = Response::Rows(vec!["x".repeat(MAX_FRAME + 16)]);
        let mut buf = Vec::new();
        let err = write_frame(&mut buf, &big).unwrap_err();
        assert!(err.to_string().contains("exceeds MAX_FRAME"), "{err}");
    }

    #[test]
    fn truncated_body_is_an_error() {
        // Declare 100 bytes but supply only 10: read_exact on the body fails.
        let mut framed = 100u32.to_be_bytes().to_vec();
        framed.extend_from_slice(&[0u8; 10]);
        assert!(read_frame::<_, Request>(&mut framed.as_slice()).is_err());
    }

    #[test]
    fn truncated_length_prefix_is_an_error() {
        let framed = [0u8; 2]; // fewer than 4 length bytes
        assert!(read_frame::<_, Request>(&mut framed.as_slice()).is_err());
    }

    #[test]
    fn runtime_dir_per_os() {
        use std::path::PathBuf;
        assert_eq!(
            runtime_dir_for("linux"),
            Some(PathBuf::from("/run/middlewhere"))
        );
        assert_eq!(
            runtime_dir_for("macos"),
            Some(PathBuf::from("/var/run/middlewhere"))
        );
        assert_eq!(runtime_dir_for("freebsd"), None);
        assert_eq!(runtime_dir_for("windows"), None);
    }
}

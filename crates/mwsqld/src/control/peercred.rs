//! Peer-credential authorization for the control channel — the security core.
//!
//! The *decision* is a pure function over already-resolved identity data
//! ([`authorize_unix`] / [`authorize_windows`]); the platform syscalls in
//! `super::unix` / `super::windows` only *populate* that data. This split keeps
//! the allow/deny logic exhaustively unit-testable without a live socket.
//!
//! Every path is FAIL-CLOSED: if the platform code cannot resolve the peer or
//! the `middlewhere-admins` group it hands us a [`AuthDecision::Deny`] — there
//! is no default-allow branch anywhere.

/// Identity of the connecting peer, captured for the audit record on BOTH allow
/// and deny. On Unix `uid`/`gid` are the connecting process's credentials
/// (`SO_PEERCRED`/`getpeereid`); on Windows they are `None` and `user` carries
/// the resolved account name (or SID string on failure).
#[derive(Debug, Clone, Default)]
pub struct PeerIdentity {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub user: String,
}

/// The authorization outcome. `Deny` carries a human-readable reason that is
/// both audited and returned to the client as `Response::Denied`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    Allow,
    Deny(String),
}

/// Resolved `middlewhere-admins` group: its gid plus the member usernames listed
/// in `/etc/group` (`gr_mem`). Populated by `getgrnam` on Unix.
#[cfg_attr(not(unix), allow(dead_code))] // unix-only in production; tested everywhere.
#[derive(Debug, Clone, Default)]
pub struct GroupInfo {
    pub gid: u32,
    pub members: Vec<String>,
}

/// The peer facts a Unix authorization decision needs: the connecting uid, the
/// peer's PRIMARY group (`pw_gid` from `getpwuid`, not the connect-time `gid`),
/// and its resolved username.
#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct UnixPeer {
    pub uid: u32,
    pub primary_gid: u32,
    pub user: String,
}

/// Pure Unix decision. Allow iff the peer is root, its primary group is
/// `middlewhere-admins`, or its username is one of the group's supplementary
/// members. `SO_PEERCRED` only exposes the connecting process's own creds, so a
/// foreign pid's supplementary groups aren't readable; the `getpwuid` +
/// `gr_mem` pair is the portable equivalent and covers `usermod -aG admins`.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn authorize_unix(peer: &UnixPeer, admins: &GroupInfo) -> AuthDecision {
    if peer.uid == 0 {
        return AuthDecision::Allow;
    }
    if peer.primary_gid == admins.gid {
        return AuthDecision::Allow;
    }
    if admins.members.iter().any(|m| m == &peer.user) {
        return AuthDecision::Allow;
    }
    AuthDecision::Deny(format!(
        "uid {} (user {:?}) is not root and not a member of the \
         middlewhere-admins group (gid {})",
        peer.uid, peer.user, admins.gid
    ))
}

/// Pure Windows decision. The platform code resolves membership via
/// `CheckTokenMembership` (race-free, on the impersonated pipe-client token);
/// this only turns the two booleans into a decision. Allow iff the client's
/// token is a member of `middlewhere-admins` OR of `BUILTIN\Administrators`.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn authorize_windows(is_admins_member: bool, is_builtin_admin: bool) -> AuthDecision {
    if is_admins_member || is_builtin_admin {
        return AuthDecision::Allow;
    }
    AuthDecision::Deny(
        "client token is not a member of middlewhere-admins or \
         BUILTIN\\Administrators"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admins() -> GroupInfo {
        GroupInfo {
            gid: 5000,
            members: vec!["alice".into(), "carol".into()],
        }
    }

    #[test]
    fn root_is_always_allowed() {
        let peer = UnixPeer {
            uid: 0,
            primary_gid: 42,
            user: "root".into(),
        };
        assert_eq!(authorize_unix(&peer, &admins()), AuthDecision::Allow);
    }

    #[test]
    fn primary_group_match_allows() {
        // Peer's primary group IS middlewhere-admins (added via `usermod -g`).
        let peer = UnixPeer {
            uid: 1001,
            primary_gid: 5000,
            user: "dave".into(),
        };
        assert_eq!(authorize_unix(&peer, &admins()), AuthDecision::Allow);
    }

    #[test]
    fn supplementary_member_allows() {
        // Peer is listed in gr_mem (the `usermod -aG` case).
        let peer = UnixPeer {
            uid: 1002,
            primary_gid: 1002,
            user: "alice".into(),
        };
        assert_eq!(authorize_unix(&peer, &admins()), AuthDecision::Allow);
    }

    #[test]
    fn non_member_is_denied() {
        let peer = UnixPeer {
            uid: 1003,
            primary_gid: 1003,
            user: "mallory".into(),
        };
        match authorize_unix(&peer, &admins()) {
            AuthDecision::Deny(r) => assert!(r.contains("middlewhere-admins"), "{r}"),
            AuthDecision::Allow => panic!("non-member must be denied"),
        }
    }

    #[test]
    fn empty_group_denies_non_root() {
        // A resolution that yielded no members and a gid nobody shares must not
        // accidentally allow (fail-closed shape of the pure fn).
        let empty = GroupInfo {
            gid: 5000,
            members: vec![],
        };
        let peer = UnixPeer {
            uid: 1004,
            primary_gid: 1004,
            user: "eve".into(),
        };
        assert!(matches!(
            authorize_unix(&peer, &empty),
            AuthDecision::Deny(_)
        ));
    }

    #[test]
    fn username_match_is_exact_not_substring() {
        // "alic" must not match member "alice".
        let peer = UnixPeer {
            uid: 1005,
            primary_gid: 1005,
            user: "alic".into(),
        };
        assert!(matches!(
            authorize_unix(&peer, &admins()),
            AuthDecision::Deny(_)
        ));
    }

    #[test]
    fn windows_admins_member_allows() {
        assert_eq!(authorize_windows(true, false), AuthDecision::Allow);
    }

    #[test]
    fn windows_builtin_admin_allows() {
        assert_eq!(authorize_windows(false, true), AuthDecision::Allow);
    }

    #[test]
    fn windows_non_member_denies() {
        match authorize_windows(false, false) {
            AuthDecision::Deny(r) => assert!(r.contains("middlewhere-admins"), "{r}"),
            AuthDecision::Allow => panic!("non-member must be denied"),
        }
    }
}

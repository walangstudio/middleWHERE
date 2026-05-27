//! AST-based query firewall (allowlist by statement kind).
//!
//! Parses every incoming statement with `sqlparser` against the MySQL dialect
//! and checks against the env's [`Policy`]. The set of allowed statement
//! variants is whitelisted — anything sqlparser parses to a variant we don't
//! explicitly allow is denied. That keeps us safe when sqlparser adds new
//! mutating statement kinds in future versions.
//!
//! Defense-in-depth: backend grants should still be `SELECT, SHOW VIEW,
//! PROCESS` so a bypass here doesn't reach mutable state.

use core::ops::ControlFlow;

use sqlparser::ast::{
    Expr, ObjectName, OneOrManyWithParens, Query, SetExpr, Statement, Visit, Visitor,
};
use sqlparser::dialect::{MySqlDialect, PostgreSqlDialect};
use sqlparser::parser::{Parser, ParserError};

use crate::config::Policy;

/// One firewall, parameterized per SQL engine. Carries the dialect parser and
/// the engine-specific denylist/allowlist. The statement-kind allowlist and
/// the `DangerVisitor` mechanism are dialect-independent and shared.
pub struct PolicyProfile {
    parse: fn(&str) -> Result<Vec<Statement>, ParserError>,
    dangerous_funcs: &'static [&'static str],
    safe_set_vars: &'static [&'static str],
}

fn parse_mysql(sql: &str) -> Result<Vec<Statement>, ParserError> {
    Parser::parse_sql(&MySqlDialect {}, sql)
}
fn parse_postgres(sql: &str) -> Result<Vec<Statement>, ParserError> {
    Parser::parse_sql(&PostgreSqlDialect {}, sql)
}

/// Functions that read the filesystem or shell out. Denied anywhere in any
/// allowed statement, at any nesting depth. Lowercased, bare name (no schema).
const MYSQL_DANGEROUS_FUNCS: &[&str] = &[
    "load_file",
    "sys_exec",
    "sys_eval",
    "sys_get",
    "lo_import",
    "lo_export",
];

/// Postgres adds server-side file/IO and out-of-band exec builtins on top of
/// the shared set. `COPY ... TO/FROM PROGRAM` is a `Statement::Copy`, already
/// default-denied by the statement-kind allowlist, so it needs no entry here.
const PG_DANGEROUS_FUNCS: &[&str] = &[
    "load_file",
    "sys_exec",
    "sys_eval",
    "sys_get",
    "lo_import",
    "lo_export",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_stat_file",
    "dblink",
    "dblink_exec",
];

/// Session variables a read-only client may set. Anything else (notably
/// `sql_mode`, `sql_log_bin`, `foreign_key_checks`, user-defined `@vars`,
/// `GLOBAL ...`) is denied. Lowercased, last path segment.
const MYSQL_SAFE_SET_VARS: &[&str] = &[
    "names",
    "autocommit",
    "time_zone",
    "character_set_client",
    "character_set_results",
    "character_set_connection",
    "collation_connection",
    "sql_safe_updates",
    "wait_timeout",
    "net_read_timeout",
    "net_write_timeout",
    "max_execution_time",
    "group_concat_max_len",
    "transaction_isolation",
    "tx_isolation",
];

/// Postgres session vars safe for a read-only client. Excludes `role`,
/// `session authorization`, and `search_path` (privilege/visibility surface).
const PG_SAFE_SET_VARS: &[&str] = &[
    "names",
    "client_encoding",
    "timezone",
    "datestyle",
    "application_name",
    "statement_timeout",
    "lock_timeout",
    "idle_in_transaction_session_timeout",
    "extra_float_digits",
    "bytea_output",
    "intervalstyle",
];

pub static MYSQL_PROFILE: PolicyProfile = PolicyProfile {
    parse: parse_mysql,
    dangerous_funcs: MYSQL_DANGEROUS_FUNCS,
    safe_set_vars: MYSQL_SAFE_SET_VARS,
};

pub static PG_PROFILE: PolicyProfile = PolicyProfile {
    parse: parse_postgres,
    dangerous_funcs: PG_DANGEROUS_FUNCS,
    safe_set_vars: PG_SAFE_SET_VARS,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(&'static str),
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            Decision::Allow => None,
            Decision::Deny(r) => Some(r),
        }
    }
}

pub fn evaluate(sql: &str, policy: &Policy, profile: &PolicyProfile) -> Decision {
    let stmts = match (profile.parse)(sql) {
        Ok(s) => s,
        Err(_) => return Decision::Deny("statement did not parse"),
    };
    if stmts.is_empty() {
        return Decision::Deny("empty statement");
    }
    let (allow_dml, allow_ddl, allow_admin) = match policy {
        Policy::ReadOnly => (false, false, false),
        Policy::ReadWrite => (true, false, false),
        Policy::Custom {
            allow_dml,
            allow_ddl,
            allow_admin,
        } => (*allow_dml, *allow_ddl, *allow_admin),
    };
    if stmts.len() > 1 && !(allow_dml && allow_ddl) {
        return Decision::Deny("multiple statements per request not allowed");
    }
    for stmt in &stmts {
        if let d @ Decision::Deny(_) =
            check_statement(stmt, allow_dml, allow_ddl, allow_admin, profile)
        {
            return d;
        }
    }
    // Statement kinds passed. Now a whole-tree pass: no dangerous function
    // call may appear anywhere in any allowed statement, at any depth
    // (function args, HAVING, JOIN ON, subqueries, ORDER BY, SET values, …).
    // This is the backstop against `SELECT IFNULL(LOAD_FILE('x'),0)` and
    // friends that a per-clause scan misses.
    for stmt in &stmts {
        if let d @ Decision::Deny(_) = scan_dangerous(stmt, profile.dangerous_funcs) {
            return d;
        }
    }
    Decision::Allow
}

fn check_statement(
    stmt: &Statement,
    allow_dml: bool,
    allow_ddl: bool,
    allow_admin: bool,
    profile: &PolicyProfile,
) -> Decision {
    use Statement::*;
    match stmt {
        // --- always-allowed reads ---
        Query(q) => check_query(q),
        ExplainTable { .. } => Decision::Allow,
        Explain { statement, .. } => {
            check_statement(statement, allow_dml, allow_ddl, allow_admin, profile)
        }
        ShowCreate { .. }
        | ShowColumns { .. }
        | ShowTables { .. }
        | ShowFunctions { .. }
        | ShowStatus { .. }
        | ShowVariables { .. }
        | ShowVariable { .. }
        | ShowDatabases { .. }
        | ShowSchemas { .. }
        | ShowCollation { .. } => Decision::Allow,
        Use { .. } => Decision::Allow,
        SetNames { .. } | SetNamesDefault { .. } => Decision::Allow,
        SetVariable {
            local,
            hivevar,
            variables,
            ..
        } => check_set(*local, *hivevar, variables, profile.safe_set_vars),

        // --- gated kinds ---
        Insert { .. } | Update { .. } | Delete { .. } if allow_dml => Decision::Allow,
        Insert { .. } | Update { .. } | Delete { .. } => {
            Decision::Deny("DML not allowed by policy")
        }

        Truncate { .. }
        | Drop { .. }
        | CreateTable { .. }
        | CreateView { .. }
        | CreateIndex { .. }
        | CreateSchema { .. }
        | CreateDatabase { .. }
        | AlterTable { .. }
        | AlterIndex { .. }
        | AlterView { .. }
            if allow_ddl =>
        {
            Decision::Allow
        }
        Truncate { .. }
        | Drop { .. }
        | CreateTable { .. }
        | CreateView { .. }
        | CreateIndex { .. }
        | CreateSchema { .. }
        | CreateDatabase { .. }
        | AlterTable { .. }
        | AlterIndex { .. }
        | AlterView { .. } => Decision::Deny("DDL not allowed by policy"),

        Grant { .. } | Revoke { .. } if allow_admin => Decision::Allow,
        Grant { .. } | Revoke { .. } => Decision::Deny("admin not allowed by policy"),

        // Transactions: harmless under ReadOnly (no writes will succeed
        // anyway) but allowing them keeps clients that wrap SELECTs in
        // BEGIN/COMMIT working.
        StartTransaction { .. } | Commit { .. } | Rollback { .. } | Savepoint { .. } => {
            Decision::Allow
        }
        SetTransaction { .. } => Decision::Allow,

        // Default: deny anything we haven't explicitly allowed. Forces an
        // affirmative decision when sqlparser learns a new variant.
        _ => Decision::Deny("statement kind not allowed by policy"),
    }
}

fn check_query(q: &Query) -> Decision {
    // `INTO OUTFILE/DUMPFILE` only ever hangs off a Select node, so the
    // recursive Query/SetOperation/Select walk below is complete for it.
    // Dangerous-function detection is handled globally by `scan_dangerous`.
    if let Some(d) = scan_select_for_outfile(&q.body) {
        return d;
    }
    Decision::Allow
}

fn scan_select_for_outfile(body: &SetExpr) -> Option<Decision> {
    match body {
        SetExpr::Select(sel) => {
            if sel.into.is_some() {
                return Some(Decision::Deny("INTO OUTFILE/DUMPFILE not allowed"));
            }
            None
        }
        SetExpr::Query(q) => scan_select_for_outfile(&q.body),
        SetExpr::SetOperation { left, right, .. } => {
            scan_select_for_outfile(left).or_else(|| scan_select_for_outfile(right))
        }
        _ => None,
    }
}

/// Last path segment of an ObjectName, lowercased (`@@global.sql_mode` →
/// `sql_mode`, `@x` → `@x`).
fn var_key(name: &ObjectName) -> String {
    name.0
        .last()
        .map(|i| i.value.to_ascii_lowercase())
        .unwrap_or_default()
}

fn check_set(
    local: bool,
    _hivevar: bool,
    vars: &OneOrManyWithParens<ObjectName>,
    safe_set_vars: &[&str],
) -> Decision {
    if local {
        return Decision::Deny("SET LOCAL not allowed by policy");
    }
    let names: Vec<&ObjectName> = match vars {
        OneOrManyWithParens::One(n) => vec![n],
        OneOrManyWithParens::Many(v) => v.iter().collect(),
    };
    for n in names {
        let full = n.to_string().to_ascii_lowercase();
        // Reject GLOBAL scope and user-defined variables outright.
        if full.contains("@@global") || full.contains("global.") {
            return Decision::Deny("SET GLOBAL not allowed by policy");
        }
        if full.starts_with('@') {
            return Decision::Deny("setting user-defined variables not allowed");
        }
        if !safe_set_vars.contains(&var_key(n).as_str()) {
            return Decision::Deny("this session variable is not on the allowlist");
        }
    }
    // Values are still subject to the global dangerous-function scan in
    // `evaluate`, so `SET autocommit = LOAD_FILE('x')` is caught there.
    Decision::Allow
}

/// Whole-statement visitor: trips on any function call whose bare name is in
/// [`DANGEROUS_FUNCS`], regardless of nesting or clause.
struct DangerVisitor<'a> {
    funcs: &'a [&'static str],
}

impl Visitor for DangerVisitor<'_> {
    type Break = &'static str;
    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<&'static str> {
        if let Expr::Function(f) = expr {
            let name = f
                .name
                .0
                .last()
                .map(|i| i.value.to_ascii_lowercase())
                .unwrap_or_default();
            if self.funcs.contains(&name.as_str()) {
                return ControlFlow::Break("dangerous builtin not allowed");
            }
        }
        ControlFlow::Continue(())
    }
}

fn scan_dangerous(stmt: &Statement, funcs: &[&'static str]) -> Decision {
    match stmt.visit(&mut DangerVisitor { funcs }) {
        ControlFlow::Break(reason) => Decision::Deny(reason),
        ControlFlow::Continue(()) => Decision::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluate(sql: &str, policy: &Policy) -> Decision {
        super::evaluate(sql, policy, &MYSQL_PROFILE)
    }

    fn deny(sql: &str) {
        let d = evaluate(sql, &Policy::ReadOnly);
        assert!(
            matches!(d, Decision::Deny(_)),
            "expected Deny for {sql:?}, got {d:?}"
        );
    }
    fn allow(sql: &str) {
        let d = evaluate(sql, &Policy::ReadOnly);
        assert_eq!(d, Decision::Allow, "expected Allow for {sql:?}, got {d:?}");
    }

    #[test]
    fn select_allowed() {
        allow("SELECT 1");
    }
    #[test]
    fn select_with_where() {
        allow("SELECT id FROM t WHERE x = 1");
    }
    #[test]
    fn show_tables_allowed() {
        allow("SHOW TABLES");
    }
    #[test]
    fn use_db_allowed() {
        allow("USE app");
    }
    #[test]
    fn explain_select_allowed() {
        allow("EXPLAIN SELECT * FROM t");
    }

    #[test]
    fn update_denied() {
        deny("UPDATE t SET x=1");
    }
    #[test]
    fn delete_denied() {
        deny("DELETE FROM t");
    }
    #[test]
    fn drop_denied() {
        deny("DROP TABLE t");
    }
    #[test]
    fn truncate_denied() {
        deny("TRUNCATE TABLE t");
    }
    #[test]
    fn alter_denied() {
        deny("ALTER TABLE t ADD COLUMN c INT");
    }
    #[test]
    fn grant_denied() {
        deny("GRANT ALL ON *.* TO 'x'@'%'");
    }
    #[test]
    fn create_table_denied() {
        deny("CREATE TABLE t (x INT)");
    }

    #[test]
    fn leading_comment_delete_denied() {
        deny("/* harmless */ DELETE FROM t");
    }
    #[test]
    fn line_comment_drop_denied() {
        deny("-- ok\nDROP TABLE t");
    }
    #[test]
    fn whitespace_delete_denied() {
        deny("   \n\t  DELETE FROM t");
    }
    #[test]
    fn stacked_statements_denied() {
        deny("SELECT 1; DELETE FROM t");
    }
    #[test]
    fn select_into_outfile_denied() {
        deny("SELECT * FROM t INTO OUTFILE '/tmp/x'");
    }
    #[test]
    fn load_file_denied() {
        deny("SELECT LOAD_FILE('/etc/passwd')");
    }

    #[test]
    fn readwrite_policy_allows_update() {
        assert_eq!(
            evaluate("UPDATE t SET x=1", &Policy::ReadWrite),
            Decision::Allow
        );
    }
    #[test]
    fn readwrite_still_denies_ddl() {
        assert!(matches!(
            evaluate("DROP TABLE t", &Policy::ReadWrite),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn unparseable_denied() {
        let d = evaluate("\x00\x00", &Policy::ReadOnly);
        assert!(matches!(d, Decision::Deny(_)));
    }

    // --- regression: AST-firewall bypasses found in the 2026-05 audit ---

    #[test]
    fn load_file_wrapped_in_function_denied() {
        deny("SELECT IFNULL(LOAD_FILE('/etc/passwd'), 0)");
        deny("SELECT CONCAT('x', LOAD_FILE('/etc/passwd'))");
        deny("SELECT HEX(LOAD_FILE('/etc/shadow'))");
    }
    #[test]
    fn load_file_in_having_denied() {
        deny("SELECT id FROM t GROUP BY id HAVING LOAD_FILE('/etc/passwd') IS NOT NULL");
    }
    #[test]
    fn load_file_in_where_subquery_denied() {
        deny("SELECT 1 FROM t WHERE x IN (SELECT LOAD_FILE('/etc/passwd'))");
    }
    #[test]
    fn load_file_in_join_on_denied() {
        deny("SELECT 1 FROM a JOIN b ON a.id = b.id AND LOAD_FILE('/x') IS NULL");
    }
    #[test]
    fn load_file_in_order_by_denied() {
        deny("SELECT id FROM t ORDER BY LOAD_FILE('/etc/passwd')");
    }
    #[test]
    fn load_file_in_cte_denied() {
        deny("WITH c AS (SELECT LOAD_FILE('/etc/passwd') v) SELECT * FROM c");
    }
    #[test]
    fn load_file_in_case_denied() {
        deny("SELECT CASE WHEN 1=1 THEN LOAD_FILE('/x') ELSE 0 END");
    }
    #[test]
    fn sys_exec_denied() {
        deny("SELECT sys_exec('rm -rf /')");
        deny("SELECT sys_eval('id')");
    }

    #[test]
    fn set_user_variable_to_load_file_denied() {
        deny("SET @x = LOAD_FILE('/etc/passwd')");
    }
    #[test]
    fn set_user_variable_denied() {
        deny("SET @x = 1");
    }
    #[test]
    fn set_sql_mode_denied() {
        deny("SET sql_mode = ''");
        deny("SET SESSION sql_mode = 'ANSI'");
    }
    #[test]
    fn set_global_denied() {
        deny("SET GLOBAL max_connections = 1");
        deny("SET @@GLOBAL.sql_log_bin = 0");
    }
    #[test]
    fn set_sql_log_bin_denied() {
        deny("SET sql_log_bin = 0");
    }
    #[test]
    fn set_allowlisted_session_vars_allowed() {
        allow("SET autocommit = 1");
        allow("SET time_zone = '+00:00'");
        allow("SET sql_safe_updates = 1");
        allow("SET NAMES utf8mb4");
        allow("SET character_set_results = NULL");
    }

    #[test]
    fn explain_hides_no_bypass() {
        deny("EXPLAIN SELECT LOAD_FILE('/etc/passwd')");
    }
}

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
    BinaryOperator, Expr, ObjectName, OneOrManyWithParens, Query, SetExpr, Statement, TableFactor,
    TransactionIsolationLevel, TransactionMode, Value, Visit, Visitor,
};
use sqlparser::dialect::{Dialect, MySqlDialect, PostgreSqlDialect};
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};

use crate::config::Policy;

/// One firewall, parameterized per SQL engine. Carries the dialect parser and
/// the engine-specific denylist/allowlist. The statement-kind allowlist and
/// the `DangerVisitor` mechanism are dialect-independent and shared.
pub struct PolicyProfile {
    dialect: &'static (dyn Dialect + Sync),
    dangerous_funcs: &'static [&'static str],
    /// Functions that write or take session-held locks: allowed only when the
    /// policy allows DML.
    write_funcs: &'static [&'static str],
    safe_set_vars: &'static [&'static str],
    /// Text the backend executes but sqlparser reads as a comment. Checked on
    /// the tokens before parsing; the AST can't see it.
    hidden_code: fn(&[Token]) -> bool,
    /// Client charsets the session may switch to. See [`MYSQL_CHARSETS`].
    safe_charsets: &'static [&'static str],
    /// Postgres aborts the open transaction on any error; MySQL does not.
    error_aborts_txn: bool,
    /// MySQL DDL implicitly commits the open transaction; Postgres DDL is
    /// transactional.
    ddl_commits: bool,
    /// InnoDB SERIALIZABLE turns plain SELECTs in a transaction into shared
    /// locking reads; Postgres SERIALIZABLE (SSI) takes no blocking locks.
    serializable_locks: bool,
}

/// MySQL runs code sqlparser treats as a comment:
/// - `/*! ... */` and MariaDB `/*M! ... */` executable comments;
/// - nested `/* /* */ ... */`: sqlparser nests, MySQL ends at the first `*/`;
/// - `--x`: MySQL needs whitespace/control after `--`, sqlparser does not.
///
/// Also denied: the `/*+ SET_VAR(...) */` optimizer hint, which sets session
/// variables for one statement and so would bypass the SET allowlist.
///
fn mysql_hidden_code(tokens: &[Token]) -> bool {
    tokens.iter().any(|t| match t {
        Token::Whitespace(Whitespace::MultiLineComment(c)) => {
            c.starts_with('!')
                || c.starts_with("M!")
                || c.contains("/*")
                || (c.starts_with('+') && c.to_ascii_lowercase().contains("set_var"))
        }
        Token::Whitespace(Whitespace::SingleLineComment { prefix, comment }) => {
            prefix == "--"
                && comment
                    .chars()
                    .next()
                    // ASCII only: MySQL ignores Unicode spaces here.
                    .is_some_and(|ch| !ch.is_ascii_whitespace() && !ch.is_ascii_control())
        }
        _ => false,
    })
}

/// Postgres comment syntax (nested `/* */`, `--` anywhere) matches sqlparser's.
fn no_hidden_code(_: &[Token]) -> bool {
    false
}

/// Functions that read the filesystem or shell out. Denied anywhere in any
/// allowed statement, at any nesting depth, under every policy. Lowercased,
/// bare name (no schema).
const MYSQL_DANGEROUS_FUNCS: &[&str] = &[
    "load_file",
    "sys_exec",
    "sys_eval",
    "sys_get",
    "lo_import",
    "lo_export",
];

/// Named locks held for the whole (pinned) session.
const MYSQL_WRITE_FUNCS: &[&str] = &["get_lock", "release_lock", "release_all_locks"];

/// Postgres adds server-side file/IO, admin, replication and out-of-band exec
/// builtins. `COPY ... TO/FROM PROGRAM` is a `Statement::Copy`, already
/// default-denied by the statement-kind allowlist, so it needs no entry here.
/// A denylist is never complete: backend grants remain the real boundary.
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
    "pg_ls_logdir",
    "pg_ls_waldir",
    "pg_ls_tmpdir",
    "pg_ls_archive_statusdir",
    "pg_ls_logicalmapdir",
    "pg_ls_logicalsnapdir",
    "pg_ls_replslotdir",
    "lo_get",
    "lo_open",
    "loread",
    "dblink",
    "dblink_exec",
    "dblink_connect",
    "dblink_connect_u",
    "dblink_disconnect",
    "dblink_send_query",
    "dblink_open",
    "dblink_fetch",
    "dblink_close",
    "dblink_get_result",
    "dblink_get_notify",
    "dblink_cancel_query",
    // set_config is SET by another name; it would bypass the SET allowlist.
    "set_config",
    "pg_terminate_backend",
    "pg_cancel_backend",
    "pg_reload_conf",
    "pg_rotate_logfile",
    "pg_promote",
    "pg_switch_wal",
    "pg_create_restore_point",
    "pg_stat_reset",
    "pg_stat_reset_shared",
    "pg_stat_reset_single_table_counters",
    "pg_stat_reset_single_function_counters",
    "pg_stat_reset_slru",
    "pg_stat_reset_replication_slot",
    "pg_create_physical_replication_slot",
    "pg_create_logical_replication_slot",
    "pg_drop_replication_slot",
    "pg_replication_slot_advance",
    "pg_logical_slot_get_changes",
    "pg_logical_slot_get_binary_changes",
    "pg_logical_slot_peek_changes",
    "pg_logical_slot_peek_binary_changes",
    "pg_logical_emit_message",
    // These run a query given as a string, which the firewall never parses.
    "query_to_xml",
    "query_to_xmlschema",
    "query_to_xml_and_xmlschema",
    "cursor_to_xml",
    "ts_stat",
    "ts_rewrite",
];

/// Writes, notifications, and advisory locks held for the whole (pinned)
/// session: fine when the policy allows DML, denied otherwise.
const PG_WRITE_FUNCS: &[&str] = &[
    "nextval",
    "setval",
    "lo_create",
    "lo_creat",
    "lo_from_bytea",
    "lo_put",
    "lo_unlink",
    "lo_truncate",
    "lowrite",
    "pg_notify",
    "pg_advisory_lock",
    "pg_advisory_lock_shared",
    "pg_advisory_xact_lock",
    "pg_advisory_xact_lock_shared",
    "pg_try_advisory_lock",
    "pg_try_advisory_lock_shared",
    "pg_try_advisory_xact_lock",
    "pg_try_advisory_xact_lock_shared",
];

/// Session variables a read-only client may set. Anything else (notably
/// `sql_mode`, `sql_log_bin`, `foreign_key_checks`, user-defined `@vars`,
/// `GLOBAL ...`) is denied. Lowercased, last path segment.
/// No `character_set_client`/`_connection`: a multibyte client charset (GBK,
/// SJIS, Big5) changes how MySQL lexes strings, while sqlparser always lexes
/// UTF-8. `SET NAMES` is checked separately against [`SAFE_CHARSETS`].
const MYSQL_SAFE_SET_VARS: &[&str] = &[
    "autocommit",
    "time_zone",
    "character_set_results",
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
/// `names`/`client_encoding` values are further limited to [`SAFE_CHARSETS`].
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

/// Session variables that set the client charset.
const CHARSET_VARS: &[&str] = &["names", "client_encoding"];

/// MySQL charsets that lex like UTF-8 for every byte sqlparser cares about
/// (quotes, backslash, comment markers), compared lowercased with `-`/`_`
/// removed. No `default`: that is whatever the server is configured with.
/// mysql_async decodes results itself, so a non-UTF-8 result charset is safe.
/// No latin1: the proxy forwards query text as UTF-8, so latin1 bytes from
/// the client would be mangled on the way in.
const MYSQL_CHARSETS: &[&str] = &["utf8", "utf8mb4", "utf8mb3", "ascii"];

/// Postgres: UTF-8 only. tokio-postgres assumes UTF-8 results, and anything
/// else makes it fail to decode rows.
const PG_CHARSETS: &[&str] = &["utf8", "unicode"];

fn safe_charset(name: &str, profile: &PolicyProfile) -> bool {
    let n = name.to_ascii_lowercase().replace(['-', '_'], "");
    profile.safe_charsets.contains(&n.as_str())
}

/// A MySQL collation implies its charset by prefix: `gbk_chinese_ci` sets
/// character_set_connection to gbk.
fn safe_collation(name: &str, profile: &PolicyProfile) -> bool {
    name.split('_')
        .next()
        .is_some_and(|c| safe_charset(c, profile))
}

/// A bare word or string literal as text (`utf8`, `'UTF8'`).
fn literal_text(e: &Expr) -> Option<&str> {
    match e {
        Expr::Identifier(i) => Some(&i.value),
        Expr::Value(Value::SingleQuotedString(s) | Value::DoubleQuotedString(s)) => Some(s),
        _ => None,
    }
}

pub static MYSQL_PROFILE: PolicyProfile = PolicyProfile {
    dialect: &MySqlDialect {},
    dangerous_funcs: MYSQL_DANGEROUS_FUNCS,
    write_funcs: MYSQL_WRITE_FUNCS,
    safe_set_vars: MYSQL_SAFE_SET_VARS,
    hidden_code: mysql_hidden_code,
    safe_charsets: MYSQL_CHARSETS,
    error_aborts_txn: false,
    ddl_commits: true,
    serializable_locks: true,
};

pub static PG_PROFILE: PolicyProfile = PolicyProfile {
    dialect: &PostgreSqlDialect {},
    dangerous_funcs: PG_DANGEROUS_FUNCS,
    write_funcs: PG_WRITE_FUNCS,
    safe_set_vars: PG_SAFE_SET_VARS,
    hidden_code: no_hidden_code,
    safe_charsets: PG_CHARSETS,
    error_aborts_txn: true,
    ddl_commits: false,
    serializable_locks: false,
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
    check(sql, policy, profile).0
}

/// [`evaluate`], plus what each statement does to the session's
/// transaction, in order, from the same parse.
pub fn check(sql: &str, policy: &Policy, profile: &PolicyProfile) -> (Decision, Vec<TxnEffect>) {
    const UNPARSED: Decision = Decision::Deny("statement did not parse");
    // Tokenize once: the comment check reads the tokens, the parser reuses them.
    let Ok(tokens) = Tokenizer::new(profile.dialect, sql).tokenize() else {
        return (UNPARSED, Vec::new());
    };
    if (profile.hidden_code)(&tokens) {
        return (
            Decision::Deny("executable or nested comment not allowed"),
            Vec::new(),
        );
    }
    let Ok(stmts) = Parser::new(profile.dialect)
        .with_tokens(tokens)
        .parse_statements()
    else {
        return (UNPARSED, Vec::new());
    };
    let effects: Vec<TxnEffect> = stmts.iter().map(txn_effect).collect();
    // The transaction status reported to the client is tracked per
    // statement, but a batch reports one outcome: whether a BEGIN or COMMIT
    // in it ran before a later statement failed is unknowable.
    if effects.len() > 1
        && effects.iter().any(|e| match e {
            TxnEffect::Work | TxnEffect::Other => false,
            // Postgres DDL is transactional: no effect on the state.
            TxnEffect::Ddl => profile.ddl_commits,
            _ => true,
        })
    {
        return (
            Decision::Deny("transaction control must be sent as its own statement"),
            effects,
        );
    }
    (decide(&stmts, policy, profile), effects)
}

fn decide(stmts: &[Statement], policy: &Policy, profile: &PolicyProfile) -> Decision {
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
    // One whole-tree pass. Every statement node at any depth must pass the
    // kind allowlist (a CTE can wrap UPDATE/INSERT inside a SELECT), every
    // query node the OUTFILE check, and no dangerous function call may appear
    // anywhere (function args, HAVING, JOIN ON, subqueries, SET values, …).
    let mut v = PolicyVisitor {
        allow_dml,
        allow_ddl,
        allow_admin,
        profile,
    };
    for stmt in stmts {
        if let ControlFlow::Break(reason) = stmt.visit(&mut v) {
            return Decision::Deny(reason);
        }
    }
    Decision::Allow
}

struct PolicyVisitor<'a> {
    allow_dml: bool,
    allow_ddl: bool,
    allow_admin: bool,
    profile: &'a PolicyProfile,
}

impl Visitor for PolicyVisitor<'_> {
    type Break = &'static str;

    fn pre_visit_statement(&mut self, stmt: &Statement) -> ControlFlow<&'static str> {
        match check_statement(
            stmt,
            self.allow_dml,
            self.allow_ddl,
            self.allow_admin,
            self.profile,
        ) {
            Decision::Deny(r) => ControlFlow::Break(r),
            Decision::Allow => ControlFlow::Continue(()),
        }
    }

    fn pre_visit_query(&mut self, q: &Query) -> ControlFlow<&'static str> {
        // FOR UPDATE / FOR SHARE locks rows for as long as the (pinned)
        // session keeps its transaction open.
        if !self.allow_dml && !q.locks.is_empty() {
            return ControlFlow::Break("locking reads not allowed by policy");
        }
        match check_query(q) {
            Decision::Deny(r) => ControlFlow::Break(r),
            Decision::Allow => ControlFlow::Continue(()),
        }
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<&'static str> {
        match expr {
            Expr::Function(f) => self.check_function(&f.name),
            _ => ControlFlow::Continue(()),
        }
    }

    /// A set-returning function in FROM (`SELECT * FROM pg_ls_dir('.')`) is a
    /// table factor, not an expression.
    fn pre_visit_table_factor(&mut self, tf: &TableFactor) -> ControlFlow<&'static str> {
        match tf {
            TableFactor::Table {
                name,
                args: Some(_),
                ..
            }
            | TableFactor::Function { name, .. } => self.check_function(name),
            _ => ControlFlow::Continue(()),
        }
    }
}

impl PolicyVisitor<'_> {
    fn check_function(&self, name: &ObjectName) -> ControlFlow<&'static str> {
        let name = var_key(name);
        if self.profile.dangerous_funcs.contains(&name.as_str()) {
            return ControlFlow::Break("dangerous builtin not allowed");
        }
        if !self.allow_dml && self.profile.write_funcs.contains(&name.as_str()) {
            return ControlFlow::Break("writing builtin not allowed by policy");
        }
        ControlFlow::Continue(())
    }
}

/// The client-visible transaction status of a session, derived from the
/// statements it ran. Drivers read it from ReadyForQuery (PG) and the OK
/// status flags (MySQL); mysql_async and tokio-postgres don't expose the
/// backend's own copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxnState {
    pub in_txn: bool,
    /// An error aborted the transaction; only ROLLBACK gets out (PG).
    pub failed: bool,
    pub autocommit: bool,
}

impl Default for TxnState {
    fn default() -> Self {
        Self {
            in_txn: false,
            failed: false,
            autocommit: true,
        }
    }
}

/// What one statement does to the session's transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxnEffect {
    Begin,
    End {
        chain: bool,
    },
    ToSavepoint,
    Autocommit(bool),
    Ddl,
    /// A query or DML: opens a transaction when autocommit is off.
    Work,
    /// SET, USE, SHOW, ...: never opens a transaction.
    Other,
}

fn txn_effect(stmt: &Statement) -> TxnEffect {
    use Statement::*;
    match stmt {
        // EXPLAIN ANALYZE runs the statement; plain EXPLAIN doesn't.
        Explain {
            analyze: true,
            statement,
            ..
        } => txn_effect(statement),
        StartTransaction { .. } => TxnEffect::Begin,
        Commit { chain }
        | Rollback {
            chain,
            savepoint: None,
        } => TxnEffect::End { chain: *chain },
        Rollback {
            savepoint: Some(_), ..
        } => TxnEffect::ToSavepoint,
        SetVariable {
            variables, value, ..
        } => assignments(variables, value)
            .into_iter()
            .rev()
            .find(|(n, _)| var_key(n) == "autocommit")
            .and_then(|(_, v)| v.and_then(autocommit_value))
            .map_or(TxnEffect::Other, TxnEffect::Autocommit),
        // MySQL: temporary tables don't implicitly commit.
        CreateTable(ct) if ct.temporary => TxnEffect::Other,
        Drop {
            temporary: true, ..
        } => TxnEffect::Other,
        Query(_) | Insert(_) | Update { .. } | Delete(_) => TxnEffect::Work,
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
        | Grant { .. }
        | Revoke { .. } => TxnEffect::Ddl,
        _ => TxnEffect::Other,
    }
}

fn autocommit_value(e: &Expr) -> Option<bool> {
    match e {
        Expr::Value(Value::Number(n, _)) => n.parse::<i64>().ok().map(|v| v != 0),
        Expr::Value(Value::Boolean(b)) => Some(*b),
        _ => match literal_text(e)?.to_ascii_lowercase().as_str() {
            "on" | "true" | "1" => Some(true),
            "off" | "false" | "0" => Some(false),
            _ => None,
        },
    }
}

impl TxnState {
    /// Update after the backend ran a statement with this effect; `ok` is
    /// whether it succeeded. Only call for statements the backend actually
    /// saw: a firewall deny never reaches it and leaves its transaction
    /// untouched.
    pub fn apply(&mut self, effects: &[TxnEffect], ok: bool, profile: &PolicyProfile) {
        for &e in effects {
            self.apply_one(e, ok, profile);
        }
    }

    fn apply_one(&mut self, effect: TxnEffect, ok: bool, profile: &PolicyProfile) {
        if !ok {
            match effect {
                // A failed COMMIT still ends the transaction (rolled back).
                TxnEffect::End { .. } => {
                    self.in_txn = false;
                    self.failed = false;
                }
                // MySQL commits before it runs the DDL, so even a failed one
                // has ended the transaction.
                TxnEffect::Ddl if profile.ddl_commits => self.in_txn = false,
                _ if self.in_txn && profile.error_aborts_txn => self.failed = true,
                // With autocommit off, InnoDB opens the transaction even for
                // a statement that then fails, and keeps its locks.
                TxnEffect::Work if !self.autocommit && !profile.error_aborts_txn => {
                    self.in_txn = true
                }
                _ => {}
            }
            return;
        }
        // Inside a failed PG transaction everything but ROLLBACK errors, so
        // any success means it is no longer failed.
        self.failed = false;
        match effect {
            TxnEffect::Begin => {
                self.in_txn = true;
                self.failed = false;
            }
            TxnEffect::End { chain } => {
                self.in_txn = chain;
                self.failed = false;
            }
            TxnEffect::ToSavepoint => self.failed = false,
            TxnEffect::Autocommit(on) => {
                // Only a switch from off to on commits; SET autocommit=1 when
                // it is already on leaves an explicit BEGIN open.
                if on && !self.autocommit {
                    self.in_txn = false;
                }
                self.autocommit = on;
            }
            TxnEffect::Ddl if profile.ddl_commits => self.in_txn = false,
            TxnEffect::Ddl | TxnEffect::Work => {
                if !self.autocommit {
                    self.in_txn = true;
                }
            }
            TxnEffect::Other => {}
        }
    }

    /// The backend rolled the transaction back on its own (MySQL deadlock).
    pub fn rolled_back(&mut self) {
        self.in_txn = false;
        self.failed = false;
    }
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
        // The body (OUTFILE, nested DML) is checked by PolicyVisitor.
        Query(_) => Decision::Allow,
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
        SetNames { charset_name, .. } if safe_charset(charset_name, profile) => Decision::Allow,
        SetNames { .. } => Decision::Deny("this client charset is not allowed"),
        SetNamesDefault { .. } => Decision::Deny("this client charset is not allowed"),
        SetVariable {
            local,
            variables,
            value,
            ..
        } => check_set(*local, variables, value, allow_dml, profile),

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
        SetTransaction { modes, .. }
            if !allow_dml
                && profile.serializable_locks
                && modes.contains(&TransactionMode::IsolationLevel(
                    TransactionIsolationLevel::Serializable,
                )) =>
        {
            Decision::Deny(SERIALIZABLE_DENIED)
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
    // Dangerous functions are checked by PolicyVisitor.
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

/// Every `(variable, value)` a SET assigns. sqlparser parses MySQL
/// `SET a=1, b=2` as variable `a` with values `[1, b = 2]`, so later
/// assignments hide in the value list as binary expressions. `b = x = y` nests
/// as `(b = x) = y`, so the name is the leftmost operand of any binary chain,
/// whatever the operator; a comparison that merely reads a variable is checked
/// too, which only ever over-denies. The value is known only for the plain
/// `name = expr` shape.
fn assignments<'a>(
    vars: &OneOrManyWithParens<ObjectName>,
    values: &'a [Expr],
) -> Vec<(ObjectName, Option<&'a Expr>)> {
    let mut out: Vec<(ObjectName, Option<&Expr>)> = match vars {
        OneOrManyWithParens::One(n) => vec![(n.clone(), values.first())],
        OneOrManyWithParens::Many(v) => v.iter().map(|n| (n.clone(), None)).collect(),
    };
    for v in values {
        let mut e = v;
        while let Expr::BinaryOp { left, .. } = e {
            e = left;
        }
        if std::ptr::eq(e, v) {
            continue;
        }
        let name = match e {
            Expr::Identifier(i) => ObjectName(vec![i.clone()]),
            Expr::CompoundIdentifier(p) => ObjectName(p.clone()),
            _ => continue,
        };
        let value = match v {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } if std::ptr::eq(left.as_ref(), e) => Some(right.as_ref()),
            _ => None,
        };
        out.push((name, value));
    }
    out
}

const SERIALIZABLE_DENIED: &str = "SERIALIZABLE (locking reads) not allowed by policy";

fn check_set(
    local: bool,
    vars: &OneOrManyWithParens<ObjectName>,
    values: &[Expr],
    allow_dml: bool,
    profile: &PolicyProfile,
) -> Decision {
    let safe_set_vars = profile.safe_set_vars;
    if local {
        return Decision::Deny("SET LOCAL not allowed by policy");
    }
    for (n, value) in assignments(vars, values) {
        let full = n.to_string().to_ascii_lowercase();
        // Reject GLOBAL scope and user-defined variables outright.
        if full.contains("@@global") || full.contains("global.") {
            return Decision::Deny("SET GLOBAL not allowed by policy");
        }
        if full.starts_with('@') {
            return Decision::Deny("setting user-defined variables not allowed");
        }
        let key = var_key(&n);
        if !safe_set_vars.contains(&key.as_str()) {
            return Decision::Deny("this session variable is not on the allowlist");
        }
        let text = value.and_then(literal_text);
        let charset_ok = if CHARSET_VARS.contains(&key.as_str()) {
            text.is_some_and(|t| safe_charset(t, profile))
        } else if key == "collation_connection" {
            text.is_some_and(|t| safe_collation(t, profile))
        } else {
            true
        };
        if !charset_ok {
            return Decision::Deny("this client charset is not allowed");
        }
        // The proxy reports autocommit to the client from this value, so it
        // must be one it can read.
        if key == "autocommit" && value.and_then(autocommit_value).is_none() {
            return Decision::Deny("autocommit must be set to a plain 0/1/ON/OFF");
        }
        if matches!(key.as_str(), "transaction_isolation" | "tx_isolation")
            && !allow_dml
            && profile.serializable_locks
            && text.map_or(true, |t| {
                t.to_ascii_lowercase().replace(['-', ' '], "") == "serializable"
                    || !t
                        .bytes()
                        .all(|b| b.is_ascii_alphabetic() || b == b'-' || b == b' ')
            })
        {
            return Decision::Deny(SERIALIZABLE_DENIED);
        }
    }
    // Values are still subject to the dangerous-function scan in
    // PolicyVisitor, so `SET autocommit = LOAD_FILE('x')` is caught there.
    Decision::Allow
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

    // --- regression: 2026-10 review ---

    fn pg(sql: &str, policy: &Policy) -> Decision {
        super::evaluate(sql, policy, &PG_PROFILE)
    }

    #[test]
    fn dml_inside_cte_denied() {
        // Asserting the reason proves these parse and are caught as DML, not
        // denied by accident as unparseable.
        const DML: Decision = Decision::Deny("DML not allowed by policy");
        assert_eq!(
            evaluate("WITH a AS (SELECT 1) UPDATE t SET x=1", &Policy::ReadOnly),
            DML
        );
        assert_eq!(
            evaluate(
                "WITH a AS (SELECT 1) INSERT INTO t VALUES (1)",
                &Policy::ReadOnly
            ),
            DML
        );
        for sql in [
            "WITH x AS (UPDATE t SET a=1 RETURNING *) SELECT * FROM x",
            "WITH x AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM x",
            "WITH a AS (SELECT 1) UPDATE t SET x=1",
        ] {
            assert_eq!(pg(sql, &Policy::ReadOnly), DML, "{sql}");
        }
        // sqlparser 0.52 can't parse DELETE in a CTE; still denied.
        assert!(!pg(
            "WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x",
            &Policy::ReadOnly
        )
        .is_allow());
    }

    #[test]
    fn dml_inside_cte_allowed_when_policy_allows_dml() {
        assert_eq!(
            pg(
                "WITH x AS (UPDATE t SET a=1 RETURNING *) SELECT * FROM x",
                &Policy::ReadWrite
            ),
            Decision::Allow
        );
    }

    #[test]
    fn plain_cte_select_allowed() {
        allow("WITH c AS (SELECT id FROM t) SELECT * FROM c");
        assert!(pg("WITH c AS (SELECT 1) SELECT * FROM c", &Policy::ReadOnly).is_allow());
    }

    #[test]
    fn mysql_executable_comments_denied() {
        deny("SELECT * FROM t /*!50000 INTO OUTFILE '/tmp/x' */");
        deny("SELECT 1 /*!50000 , LOAD_FILE('/etc/passwd') */");
        deny("SELECT 1 /*! ; DELETE FROM t */");
        deny("SELECT 1 /*M!100000 , LOAD_FILE('/etc/passwd') */");
    }

    #[test]
    fn mysql_dash_dash_without_space_denied() {
        deny("SELECT 1 --1, LOAD_FILE('/etc/passwd')");
    }

    #[test]
    fn mysql_nested_comment_denied() {
        // MySQL ends the comment at the first `*/` and runs LOAD_FILE.
        deny("SELECT 1 /* /* */ , LOAD_FILE('/etc/passwd') # */");
    }

    #[test]
    fn ordinary_comments_and_comment_like_strings_allowed() {
        allow("SELECT 1 -- trailing comment");
        allow("SELECT 1 --\nFROM DUAL");
        allow("SELECT 1 /* plain */");
        allow("SELECT 1 # hash comment");
        allow("SELECT '/*!50000 x */', '--1'");
    }

    #[test]
    fn multi_assignment_set_checks_every_variable() {
        const NOT_LISTED: Decision =
            Decision::Deny("this session variable is not on the allowlist");
        assert_eq!(
            evaluate("SET autocommit=1, sql_mode=''", &Policy::ReadOnly),
            NOT_LISTED
        );
        assert_eq!(
            evaluate(
                "SET time_zone='+00:00', foreign_key_checks=0",
                &Policy::ReadOnly
            ),
            NOT_LISTED
        );
        deny("SET autocommit=1, @x=1");
        deny("SET autocommit=1, @@global.sql_log_bin=0");
        allow("SET autocommit=1, time_zone='+00:00'");
    }

    #[test]
    fn pg_dangerous_builtins_denied() {
        for sql in [
            "SELECT set_config('search_path','evil',false)",
            "SELECT pg_ls_waldir()",
            "SELECT lo_get(1234)",
            "SELECT lo_from_bytea(0, 'x')",
            "SELECT dblink_connect('host=evil')",
            "SELECT pg_terminate_backend(1)",
            "SELECT pg_reload_conf()",
            "SELECT nextval('s')",
            "SELECT query_to_xml('DELETE FROM t RETURNING 1', true, false, '')",
        ] {
            assert!(!pg(sql, &Policy::ReadOnly).is_allow(), "{sql}");
        }
    }

    #[test]
    fn dangerous_function_in_from_clause_denied() {
        for sql in [
            "SELECT * FROM pg_ls_dir('.')",
            "SELECT * FROM pg_ls_waldir()",
            "SELECT * FROM dblink('host=evil', 'SELECT 1') AS t(x int)",
            "SELECT * FROM t, LATERAL pg_ls_dir('.') AS d",
        ] {
            assert!(!pg(sql, &Policy::ReadOnly).is_allow(), "{sql}");
        }
        assert!(pg("SELECT * FROM generate_series(1, 3)", &Policy::ReadOnly).is_allow());
    }

    #[test]
    fn set_assignment_hidden_behind_nested_comparison_denied() {
        deny("SET autocommit=1, sql_mode = '' = ''");
        deny("SET autocommit=1, sql_mode = 1 + 1");
        deny("SET autocommit=1, sql_mode := ''");
    }

    #[test]
    fn dash_dash_followed_by_unicode_space_denied() {
        deny("SELECT 1 --\u{a0}, LOAD_FILE('/etc/passwd')");
        deny("SELECT 1 --\u{85}, LOAD_FILE('/etc/passwd')");
    }

    #[test]
    fn multibyte_client_charsets_denied() {
        deny("SET NAMES gbk");
        deny("SET NAMES sjis");
        deny("SET character_set_client = 'big5'");
        deny("SET autocommit=1, character_set_connection='gbk'");
        allow("SET NAMES utf8mb4");
        allow("SET NAMES ascii");
        for sql in ["SET client_encoding = 'SJIS'", "SET NAMES 'BIG5'"] {
            assert!(!pg(sql, &Policy::ReadOnly).is_allow(), "{sql}");
        }
        for sql in [
            "SET client_encoding = 'UTF8'",
            "SET client_encoding TO 'utf-8'",
        ] {
            assert!(pg(sql, &Policy::ReadOnly).is_allow(), "{sql}");
        }
    }

    /// Drive a TxnState the way the routers do: effect from `check`.
    trait Run {
        fn after(&mut self, sql: &str, ok: bool, profile: &PolicyProfile);
    }
    impl Run for TxnState {
        fn after(&mut self, sql: &str, ok: bool, profile: &PolicyProfile) {
            let (_, effects) = check(sql, &Policy::ReadWrite, profile);
            self.apply(&effects, ok, profile);
        }
    }

    #[test]
    fn txn_state_tracks_begin_error_and_rollback() {
        let mut t = TxnState::default();
        t.after("SELECT 1", true, &PG_PROFILE);
        assert!(!t.in_txn);
        t.after("BEGIN", true, &PG_PROFILE);
        assert!(t.in_txn && !t.failed);
        t.after("SELECT boom", false, &PG_PROFILE);
        assert!(t.failed, "a PG error aborts the transaction");
        t.after("ROLLBACK", true, &PG_PROFILE);
        assert_eq!(t, TxnState::default());

        let mut m = TxnState::default();
        m.after("START TRANSACTION", true, &MYSQL_PROFILE);
        m.after("SELECT boom", false, &MYSQL_PROFILE);
        assert!(
            m.in_txn && !m.failed,
            "a MySQL error leaves the transaction open"
        );
        m.after("COMMIT", true, &MYSQL_PROFILE);
        assert!(!m.in_txn);
        m.after("SET autocommit = 0", true, &MYSQL_PROFILE);
        assert!(!m.autocommit && !m.in_txn);
        m.after("SELECT 1", true, &MYSQL_PROFILE);
        assert!(
            m.in_txn,
            "with autocommit off any statement opens a transaction"
        );
        m.after("SET autocommit = 1", true, &MYSQL_PROFILE);
        assert!(m.autocommit && !m.in_txn);
    }

    #[test]
    fn txn_state_reads_every_autocommit_spelling_and_ddl_commit() {
        for off in [
            "SET autocommit = 0",
            "SET autocommit = 'OFF'",
            "SET autocommit = off",
            "SET autocommit = false",
            "SET time_zone = '+00:00', autocommit = 0",
        ] {
            let mut m = TxnState::default();
            m.after(off, true, &MYSQL_PROFILE);
            assert!(!m.autocommit, "{off}");
        }
        let mut m = TxnState::default();
        m.after("BEGIN", true, &MYSQL_PROFILE);
        m.after("CREATE TABLE t (x INT)", true, &MYSQL_PROFILE);
        assert!(!m.in_txn, "MySQL DDL implicitly commits");
        let mut p = TxnState::default();
        p.after("BEGIN", true, &PG_PROFILE);
        p.after("CREATE TABLE t (x INT)", true, &PG_PROFILE);
        assert!(p.in_txn, "Postgres DDL is transactional");
    }

    #[test]
    fn txn_state_round3_cases() {
        let my = &MYSQL_PROFILE;
        let mut m = TxnState::default();
        m.after("SET autocommit = 0", true, my);
        m.after("SET time_zone = '+00:00'", true, my);
        assert!(!m.in_txn, "SET does not open a transaction");
        m.after("SELECT 1", true, my);
        assert!(m.in_txn);

        let mut m = TxnState::default();
        m.after("BEGIN", true, my);
        m.after("CREATE TEMPORARY TABLE t (x INT)", true, my);
        assert!(m.in_txn, "temporary tables don't commit");
        m.after("ALTER TABLE missing ADD c INT", false, my);
        assert!(!m.in_txn, "a failed DDL already committed");

        let mut m = TxnState::default();
        m.after("SET autocommit = 0, autocommit = 1", true, my);
        assert!(m.autocommit, "the last assignment wins");

        let mut p = TxnState::default();
        let (_, effects) = check("BEGIN; SELECT 1", &Policy::ReadWrite, &PG_PROFILE);
        p.apply(&effects, true, &PG_PROFILE);
        assert!(p.in_txn, "every statement of a batch counts");
    }

    #[test]
    fn txn_state_round4_cases() {
        let mut p = TxnState::default();
        p.after("BEGIN", true, &PG_PROFILE);
        p.after("COMMIT", false, &PG_PROFILE);
        assert_eq!(
            p,
            TxnState::default(),
            "a failed COMMIT ends the transaction"
        );
        deny("BEGIN; SELECT 1");
        assert!(!pg("BEGIN; SELECT 1/0", &Policy::ReadWrite).is_allow());
        assert!(!pg(
            "COMMIT; SELECT 1",
            &Policy::Custom {
                allow_dml: true,
                allow_ddl: true,
                allow_admin: false
            }
        )
        .is_allow());
    }

    #[test]
    fn pg_client_encoding_is_utf8_only() {
        for sql in [
            "SET client_encoding = 'LATIN1'",
            "SET NAMES 'LATIN1'",
            "SET client_encoding = 'SQL_ASCII'",
        ] {
            assert!(!pg(sql, &Policy::ReadOnly).is_allow(), "{sql}");
        }
        deny("SET NAMES latin1");
        allow("SET NAMES utf8mb4");
    }

    #[test]
    fn txn_state_round5_cases() {
        let my = &MYSQL_PROFILE;
        let mut m = TxnState::default();
        m.after("BEGIN", true, my);
        m.after("SET autocommit = 1", true, my);
        assert!(m.in_txn, "autocommit already on: BEGIN stays open");

        let mut m = TxnState::default();
        m.after("SET autocommit = 0", true, my);
        m.after("INSERT INTO t VALUES (1)", false, my);
        assert!(m.in_txn, "a failed statement still opened the transaction");

        let mut m = TxnState::default();
        m.after("SET autocommit = 0", true, my);
        m.after("EXPLAIN ANALYZE SELECT * FROM t", true, my);
        assert!(m.in_txn, "EXPLAIN ANALYZE runs the statement");

        let ddl = Policy::Custom {
            allow_dml: true,
            allow_ddl: true,
            allow_admin: false,
        };
        assert!(pg("CREATE TABLE a (x int); CREATE INDEX ai ON a (x)", &ddl).is_allow());
        assert!(!evaluate("CREATE TABLE a (x int); CREATE INDEX ai ON a (x)", &ddl).is_allow());
    }

    #[test]
    fn unreadable_autocommit_values_denied() {
        for sql in [
            "SET autocommit = (0)",
            "SET autocommit = 1 - 1",
            "SET autocommit = DEFAULT",
        ] {
            deny(sql);
        }
        allow("SET autocommit = 00");
        allow("SET autocommit = ON");
    }

    #[test]
    fn serializable_needs_dml_on_mysql() {
        const DENIED: Decision = Decision::Deny(SERIALIZABLE_DENIED);
        for sql in [
            "SET transaction_isolation = 'SERIALIZABLE'",
            "SET tx_isolation = 'serializable'",
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
        ] {
            assert_eq!(evaluate(sql, &Policy::ReadOnly), DENIED, "{sql}");
        }
        allow("SET transaction_isolation = 'READ-COMMITTED'");
        allow("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
        assert!(evaluate(
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
            &Policy::ReadWrite
        )
        .is_allow());
        assert!(pg(
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
            &Policy::ReadOnly
        )
        .is_allow());
    }

    #[test]
    fn locking_reads_need_dml() {
        deny("SELECT * FROM t FOR UPDATE");
        deny("SELECT * FROM t FOR SHARE NOWAIT");
        assert!(!pg("SELECT * FROM t FOR UPDATE", &Policy::ReadOnly).is_allow());
        assert!(evaluate("SELECT * FROM t FOR UPDATE", &Policy::ReadWrite).is_allow());
    }

    #[test]
    fn write_and_lock_builtins_need_dml() {
        deny("SELECT GET_LOCK('x', 10)");
        for sql in [
            "SELECT nextval('s')",
            "SELECT pg_advisory_lock(1)",
            "SELECT pg_notify('c', 'x')",
        ] {
            assert!(!pg(sql, &Policy::ReadOnly).is_allow(), "{sql}");
            assert!(pg(sql, &Policy::ReadWrite).is_allow(), "{sql}");
        }
    }

    #[test]
    fn more_pg_dangerous_builtins_denied() {
        for sql in [
            "SELECT ts_rewrite('a'::tsquery, 'SELECT 1')",
            "SELECT * FROM pg_logical_slot_get_changes('s', NULL, NULL)",
            "SELECT pg_stat_reset()",
            "SELECT dblink_disconnect()",
        ] {
            assert!(!pg(sql, &Policy::ReadWrite).is_allow(), "{sql}");
        }
    }

    #[test]
    fn set_var_hint_denied_but_other_hints_allowed() {
        deny("SELECT /*+ SET_VAR(foreign_key_checks=0) */ 1");
        deny("SELECT /*+ set_var(sql_mode='') */ 1");
        allow("SELECT /*+ MAX_EXECUTION_TIME(1000) */ 1");
    }

    #[test]
    fn charset_defaults_and_collations_checked() {
        deny("SET NAMES DEFAULT");
        deny("SET collation_connection = 'gbk_chinese_ci'");
        deny("SET autocommit=1, collation_connection='big5_chinese_ci'");
        allow("SET collation_connection = 'utf8mb4_0900_ai_ci'");
    }

    #[test]
    fn pg_comments_still_allowed() {
        assert!(pg("SELECT 1 --1", &Policy::ReadOnly).is_allow());
        assert!(pg("SELECT 1 /* a /* b */ c */", &Policy::ReadOnly).is_allow());
    }
}

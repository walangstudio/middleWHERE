//! PostgreSQL v3 frontend/backend message framing.
//!
//! Wire layout: regular messages are `[type:u8][len:i32 BE][payload]` where
//! `len` counts itself but not the type byte. The startup packet is special:
//! it has no type byte, just `[len:i32][payload]`.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_3_0: i32 = 196608;
pub const SSL_REQUEST_CODE: i32 = 80877103;
pub const GSSENC_REQUEST_CODE: i32 = 80877104;
pub const CANCEL_REQUEST_CODE: i32 = 80877102;

#[derive(Debug, thiserror::Error)]
pub enum PgProtoError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("client closed")]
    Closed,
    #[error("malformed: {0}")]
    Malformed(&'static str),
}

/// Outcome of reading the connection's opening packet.
pub enum Startup {
    /// A real StartupMessage with its parameter key/value pairs.
    Params(Vec<(String, String)>),
    /// Client asked for SSL or GSSAPI encryption (we answer 'N' and loop).
    EncryptionRequest,
    /// CancelRequest — we don't support out-of-band cancel; caller closes.
    Cancel,
}

async fn read_exact<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> Result<(), PgProtoError> {
    match r.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(PgProtoError::Closed),
        Err(e) => Err(PgProtoError::Io(e)),
    }
}

/// Read one startup-phase packet (no type byte).
pub async fn read_startup<R: AsyncRead + Unpin>(r: &mut R) -> Result<Startup, PgProtoError> {
    let mut len_b = [0u8; 4];
    read_exact(r, &mut len_b).await?;
    let len = i32::from_be_bytes(len_b);
    if !(8..=10_000).contains(&len) {
        return Err(PgProtoError::Malformed("startup length out of range"));
    }
    let mut body = vec![0u8; (len - 4) as usize];
    read_exact(r, &mut body).await?;
    if body.len() < 4 {
        return Err(PgProtoError::Malformed("startup body too short"));
    }
    let code = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    match code {
        SSL_REQUEST_CODE | GSSENC_REQUEST_CODE => Ok(Startup::EncryptionRequest),
        CANCEL_REQUEST_CODE => Ok(Startup::Cancel),
        PROTOCOL_3_0 => {
            let mut params = Vec::new();
            let kv = &body[4..];
            let mut it = kv.split(|&b| b == 0);
            loop {
                let k = match it.next() {
                    Some(k) if !k.is_empty() => k,
                    _ => break,
                };
                let v = it.next().unwrap_or(&[]);
                params.push((
                    String::from_utf8_lossy(k).into_owned(),
                    String::from_utf8_lossy(v).into_owned(),
                ));
            }
            Ok(Startup::Params(params))
        }
        _ => Err(PgProtoError::Malformed("unsupported protocol version")),
    }
}

/// Read one typed message: returns `(type_byte, payload)`.
pub async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> Result<(u8, Vec<u8>), PgProtoError> {
    let mut hdr = [0u8; 5];
    read_exact(r, &mut hdr).await?;
    let tag = hdr[0];
    let len = i32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
    if !(4..=64 * 1024 * 1024).contains(&len) {
        return Err(PgProtoError::Malformed("message length out of range"));
    }
    let mut body = vec![0u8; (len - 4) as usize];
    read_exact(r, &mut body).await?;
    Ok((tag, body))
}

pub async fn write_raw<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<(), PgProtoError> {
    w.write_all(bytes).await?;
    Ok(())
}

/// Frame a typed message: `[tag][len:i32 = 4+payload][payload]`.
pub fn msg(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(tag);
    out.extend_from_slice(&((payload.len() as i32 + 4).to_be_bytes()));
    out.extend_from_slice(payload);
    out
}

fn put_cstr(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(s);
    buf.push(0);
}

/// `AuthenticationCleartextPassword` ('R', code 3).
pub fn auth_cleartext_request() -> Vec<u8> {
    msg(b'R', &3i32.to_be_bytes())
}

/// `AuthenticationOk` ('R', code 0).
pub fn auth_ok() -> Vec<u8> {
    msg(b'R', &0i32.to_be_bytes())
}

pub fn parameter_status(key: &str, val: &str) -> Vec<u8> {
    let mut p = Vec::new();
    put_cstr(&mut p, key.as_bytes());
    put_cstr(&mut p, val.as_bytes());
    msg(b'S', &p)
}

pub fn backend_key_data(pid: i32, secret: i32) -> Vec<u8> {
    let mut p = Vec::with_capacity(8);
    p.extend_from_slice(&pid.to_be_bytes());
    p.extend_from_slice(&secret.to_be_bytes());
    msg(b'K', &p)
}

/// `ReadyForQuery` ('Z') with transaction status 'I' (idle).
pub fn ready_for_query() -> Vec<u8> {
    msg(b'Z', b"I")
}

/// `ErrorResponse` ('E') with Severity/Code/Message fields.
pub fn error_response(sqlstate: &str, message: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(b'S');
    put_cstr(&mut p, b"ERROR");
    p.push(b'V');
    put_cstr(&mut p, b"ERROR");
    p.push(b'C');
    put_cstr(&mut p, sqlstate.as_bytes());
    p.push(b'M');
    put_cstr(&mut p, message.as_bytes());
    p.push(0);
    msg(b'E', &p)
}

/// `RowDescription` ('T'). Real per-column type OIDs (from a backend
/// prepare) so the client decodes text values correctly. All values are
/// sent in text format.
pub fn row_description(cols: &[(String, i32)]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&(cols.len() as i16).to_be_bytes());
    for (name, oid) in cols {
        put_cstr(&mut p, name.as_bytes());
        p.extend_from_slice(&0i32.to_be_bytes()); // table OID
        p.extend_from_slice(&0i16.to_be_bytes()); // column attr no.
        p.extend_from_slice(&oid.to_be_bytes()); // type OID
        p.extend_from_slice(&(-1i16).to_be_bytes()); // type size (var)
        p.extend_from_slice(&(-1i32).to_be_bytes()); // type modifier
        p.extend_from_slice(&0i16.to_be_bytes()); // format = text
    }
    msg(b'T', &p)
}

/// `DataRow` ('D'). `None` cell => SQL NULL.
pub fn data_row(cells: &[Option<Vec<u8>>]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&(cells.len() as i16).to_be_bytes());
    for c in cells {
        match c {
            None => p.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(b) => {
                p.extend_from_slice(&(b.len() as i32).to_be_bytes());
                p.extend_from_slice(b);
            }
        }
    }
    msg(b'D', &p)
}

pub fn command_complete(tag: &str) -> Vec<u8> {
    let mut p = Vec::new();
    put_cstr(&mut p, tag.as_bytes());
    msg(b'C', &p)
}

// --- Extended query protocol ---

pub fn parse_complete() -> Vec<u8> {
    msg(b'1', &[])
}
pub fn bind_complete() -> Vec<u8> {
    msg(b'2', &[])
}
pub fn close_complete() -> Vec<u8> {
    msg(b'3', &[])
}
pub fn no_data() -> Vec<u8> {
    msg(b'n', &[])
}
pub fn empty_query_response() -> Vec<u8> {
    msg(b'I', &[])
}

/// `ParameterDescription` ('t'): int16 count + int32 type-oid per param.
pub fn parameter_description(oids: &[i32]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&(oids.len() as i16).to_be_bytes());
    for o in oids {
        p.extend_from_slice(&o.to_be_bytes());
    }
    msg(b't', &p)
}

fn read_cstr(buf: &[u8], pos: &mut usize) -> String {
    let start = *pos;
    while *pos < buf.len() && buf[*pos] != 0 {
        *pos += 1;
    }
    let s = String::from_utf8_lossy(&buf[start..*pos]).into_owned();
    if *pos < buf.len() {
        *pos += 1; // skip NUL
    }
    s
}

fn read_i16(buf: &[u8], pos: &mut usize) -> i16 {
    let v = i16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
    *pos += 2;
    v
}

fn read_i32(buf: &[u8], pos: &mut usize) -> i32 {
    let v = i32::from_be_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]);
    *pos += 4;
    v
}

pub struct ParseMsg {
    pub stmt: String,
    pub query: String,
}

pub fn parse_parse(body: &[u8]) -> Option<ParseMsg> {
    // We only need the statement name and query text; the client-declared
    // param type OIDs are ignored — authoritative types come from the
    // backend Parse+Describe in `backend_describe`.
    let mut p = 0;
    let stmt = read_cstr(body, &mut p);
    let query = read_cstr(body, &mut p);
    Some(ParseMsg { stmt, query })
}

pub struct BindMsg {
    pub portal: String,
    pub stmt: String,
    /// One format code per parameter (0 = text, 1 = binary). Already
    /// normalized: if the client sent a single code it is broadcast.
    pub param_formats: Vec<i16>,
    /// `None` = SQL NULL.
    pub params: Vec<Option<Vec<u8>>>,
}

pub fn parse_bind(body: &[u8]) -> Option<BindMsg> {
    let mut p = 0;
    let portal = read_cstr(body, &mut p);
    let stmt = read_cstr(body, &mut p);
    let nfmt = read_i16(body, &mut p).max(0) as usize;
    let mut fmts = Vec::with_capacity(nfmt);
    for _ in 0..nfmt {
        fmts.push(read_i16(body, &mut p));
    }
    let nparams = read_i16(body, &mut p).max(0) as usize;
    let mut params = Vec::with_capacity(nparams);
    for _ in 0..nparams {
        let len = read_i32(body, &mut p);
        if len < 0 {
            params.push(None);
        } else {
            let len = len as usize;
            params.push(Some(body[p..p + len].to_vec()));
            p += len;
        }
    }
    // Normalize formats to one-per-param.
    let param_formats = (0..nparams)
        .map(|i| match nfmt {
            0 => 0,
            1 => fmts[0],
            _ => *fmts.get(i).unwrap_or(&0),
        })
        .collect();
    Some(BindMsg {
        portal,
        stmt,
        param_formats,
        params,
    })
}

/// Describe/Close target: ('S', name) statement or ('P', name) portal.
pub fn parse_describe_or_close(body: &[u8]) -> Option<(u8, String)> {
    if body.is_empty() {
        return None;
    }
    let kind = body[0];
    let mut p = 1;
    let name = read_cstr(body, &mut p);
    Some((kind, name))
}

pub fn parse_execute(body: &[u8]) -> Option<String> {
    let mut p = 0;
    Some(read_cstr(body, &mut p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn len_of(m: &[u8]) -> i32 {
        i32::from_be_bytes([m[1], m[2], m[3], m[4]])
    }

    #[test]
    fn framing_msg_len_includes_self() {
        let m = msg(b'X', b"abc");
        assert_eq!(m[0], b'X');
        assert_eq!(len_of(&m), 7); // 4 + 3
        assert_eq!(&m[5..], b"abc");
        assert_eq!(msg(b'1', &[]), vec![b'1', 0, 0, 0, 4]);
    }

    #[test]
    fn fixed_builders() {
        assert_eq!(parse_complete(), vec![b'1', 0, 0, 0, 4]);
        assert_eq!(bind_complete(), vec![b'2', 0, 0, 0, 4]);
        assert_eq!(close_complete(), vec![b'3', 0, 0, 0, 4]);
        assert_eq!(no_data(), vec![b'n', 0, 0, 0, 4]);
        assert_eq!(ready_for_query(), vec![b'Z', 0, 0, 0, 5, b'I']);
        assert_eq!(auth_ok(), vec![b'R', 0, 0, 0, 8, 0, 0, 0, 0]);
        assert_eq!(auth_cleartext_request(), vec![b'R', 0, 0, 0, 8, 0, 0, 0, 3]);
    }

    #[test]
    fn error_response_fields() {
        let e = error_response("42501", "nope");
        assert_eq!(e[0], b'E');
        let body = &e[5..];
        assert!(body.starts_with(b"SERROR\0"));
        assert!(body.windows(7).any(|w| w == b"C42501\0"));
        assert!(body.windows(6).any(|w| w == b"Mnope\0"));
        assert_eq!(*body.last().unwrap(), 0); // terminator
    }

    #[test]
    fn row_description_and_data_row() {
        let t = row_description(&[("id".into(), 23), ("name".into(), 25)]);
        assert_eq!(t[0], b'T');
        assert_eq!(i16::from_be_bytes([t[5], t[6]]), 2); // field count
        let d = data_row(&[Some(b"5".to_vec()), None]);
        assert_eq!(d[0], b'D');
        assert_eq!(i16::from_be_bytes([d[5], d[6]]), 2);
        // col1: len 1, '5'; col2: len -1
        assert_eq!(&d[7..11], &1i32.to_be_bytes());
        assert_eq!(d[11], b'5');
        assert_eq!(&d[12..16], &(-1i32).to_be_bytes());
    }

    #[test]
    fn parameter_description_and_command_complete() {
        let pd = parameter_description(&[23, 25]);
        assert_eq!(pd[0], b't');
        assert_eq!(i16::from_be_bytes([pd[5], pd[6]]), 2);
        let cc = command_complete("SELECT 3");
        assert_eq!(cc[0], b'C');
        assert_eq!(&cc[5..], b"SELECT 3\0");
    }

    #[test]
    fn parse_parse_extracts_stmt_and_query() {
        let mut body = Vec::new();
        body.extend_from_slice(b"st\0");
        body.extend_from_slice(b"SELECT $1\0");
        body.extend_from_slice(&0i16.to_be_bytes()); // 0 param types
        let m = parse_parse(&body).unwrap();
        assert_eq!(m.stmt, "st");
        assert_eq!(m.query, "SELECT $1");
    }

    #[test]
    fn parse_bind_formats_broadcast_and_nulls() {
        let mut body = Vec::new();
        body.extend_from_slice(b"por\0");
        body.extend_from_slice(b"st\0");
        body.extend_from_slice(&1i16.to_be_bytes()); // 1 format code...
        body.extend_from_slice(&1i16.to_be_bytes()); // ...= binary, broadcast
        body.extend_from_slice(&2i16.to_be_bytes()); // 2 params
        body.extend_from_slice(&3i32.to_be_bytes()); // p1 len 3
        body.extend_from_slice(b"abc");
        body.extend_from_slice(&(-1i32).to_be_bytes()); // p2 NULL
        body.extend_from_slice(&0i16.to_be_bytes()); // 0 result formats
        let m = parse_bind(&body).unwrap();
        assert_eq!(m.portal, "por");
        assert_eq!(m.stmt, "st");
        assert_eq!(m.param_formats, vec![1, 1]); // broadcast to both
        assert_eq!(m.params, vec![Some(b"abc".to_vec()), None]);
    }

    #[test]
    fn describe_close_execute_parse() {
        let mut b = vec![b'S'];
        b.extend_from_slice(b"name\0");
        assert_eq!(
            parse_describe_or_close(&b),
            Some((b'S', "name".to_string()))
        );
        assert_eq!(
            parse_execute(b"portal\0\0\0\0\0"),
            Some("portal".to_string())
        );
    }

    #[tokio::test]
    async fn read_startup_params_ssl_cancel() {
        // StartupMessage: len(self+body) | proto 3.0 | k\0v\0..\0
        let mut sm = Vec::new();
        let kv = b"user\0pgenv\0database\0db\0\0";
        sm.extend_from_slice(&((kv.len() as i32 + 8).to_be_bytes()));
        sm.extend_from_slice(&PROTOCOL_3_0.to_be_bytes());
        sm.extend_from_slice(kv);
        match read_startup(&mut sm.as_slice()).await.unwrap() {
            Startup::Params(p) => {
                assert!(p.contains(&("user".into(), "pgenv".into())));
                assert!(p.contains(&("database".into(), "db".into())));
            }
            _ => panic!("expected Params"),
        }
        let mut ssl = Vec::new();
        ssl.extend_from_slice(&8i32.to_be_bytes());
        ssl.extend_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
        assert!(matches!(
            read_startup(&mut ssl.as_slice()).await.unwrap(),
            Startup::EncryptionRequest
        ));
        let mut cancel = Vec::new();
        cancel.extend_from_slice(&16i32.to_be_bytes());
        cancel.extend_from_slice(&CANCEL_REQUEST_CODE.to_be_bytes());
        cancel.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            read_startup(&mut cancel.as_slice()).await.unwrap(),
            Startup::Cancel
        ));
    }

    #[tokio::test]
    async fn read_message_roundtrip() {
        let framed = msg(b'Q', b"SELECT 1\0");
        let (tag, body) = read_message(&mut framed.as_slice()).await.unwrap();
        assert_eq!(tag, b'Q');
        assert_eq!(body, b"SELECT 1\0");
    }
}

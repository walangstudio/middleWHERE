//! Binary result format, encoded from the backend's text output.
//!
//! The backend runs statements through the simple-query protocol, so every
//! value arrives as text. A client that asked for binary results (pgjdbc does,
//! once a statement is server-prepared) gets the text re-encoded here. Text
//! input is what Postgres prints with `DateStyle=ISO` and `bytea_output` hex
//! or escape: pgjdbc requires ISO and refuses to run otherwise.

/// Binary-capable result types: the ones pgjdbc asks for, and the text-like
/// and common scalar types drivers that want binary for every column use.
pub fn supported(oid: i32) -> bool {
    matches!(
        oid,
        BOOL | BYTEA | INT8 | INT2 | INT4 | OID | FLOAT4 | FLOAT8 | POINT | BOX
    ) || matches!(
        oid,
        DATE | TIME | TIMESTAMP | TIMESTAMPTZ | TIMETZ | NUMERIC | UUID
    ) || matches!(oid, TEXT | VARCHAR | BPCHAR | NAME | CHAR | JSON | JSONB)
        || array_elem(oid).is_some()
}

/// Encode one text value as `oid`'s binary form. Caller checks [`supported`].
pub fn encode(oid: i32, text: &[u8]) -> Result<Vec<u8>, &'static str> {
    let s = std::str::from_utf8(text).map_err(|_| BAD)?;
    if let Some(elem) = array_elem(oid) {
        return encode_array(elem, s);
    }
    encode_scalar(oid, s)
}

const BAD: &str = "result value does not parse for binary format";

const BOOL: i32 = 16;
const CHAR: i32 = 18;
const NAME: i32 = 19;
const JSON: i32 = 114;
const BPCHAR: i32 = 1042;
const JSONB: i32 = 3802;
const BYTEA: i32 = 17;
const INT8: i32 = 20;
const INT2: i32 = 21;
const INT4: i32 = 23;
const TEXT: i32 = 25;
const OID: i32 = 26;
const POINT: i32 = 600;
const BOX: i32 = 603;
const FLOAT4: i32 = 700;
const FLOAT8: i32 = 701;
const VARCHAR: i32 = 1043;
const DATE: i32 = 1082;
const TIME: i32 = 1083;
const TIMESTAMP: i32 = 1114;
const TIMESTAMPTZ: i32 = 1184;
const TIMETZ: i32 = 1266;
const NUMERIC: i32 = 1700;
const UUID: i32 = 2950;

fn array_elem(oid: i32) -> Option<i32> {
    Some(match oid {
        1000 => BOOL,
        1001 => BYTEA,
        1005 => INT2,
        1007 => INT4,
        1009 => TEXT,
        1015 => VARCHAR,
        1016 => INT8,
        1021 => FLOAT4,
        1022 => FLOAT8,
        1028 => OID,
        _ => return None,
    })
}

fn encode_scalar(oid: i32, s: &str) -> Result<Vec<u8>, &'static str> {
    Ok(match oid {
        BOOL => vec![match s {
            "t" => 1,
            "f" => 0,
            _ => return Err(BAD),
        }],
        INT2 => s.parse::<i16>().map_err(|_| BAD)?.to_be_bytes().to_vec(),
        INT4 => s.parse::<i32>().map_err(|_| BAD)?.to_be_bytes().to_vec(),
        OID => s.parse::<u32>().map_err(|_| BAD)?.to_be_bytes().to_vec(),
        INT8 => s.parse::<i64>().map_err(|_| BAD)?.to_be_bytes().to_vec(),
        FLOAT4 => match s {
            "NaN" | "Infinity" | "-Infinity" => float(s)? as f32,
            _ => s.parse::<f32>().map_err(|_| BAD)?,
        }
        .to_be_bytes()
        .to_vec(),
        FLOAT8 => float(s)?.to_be_bytes().to_vec(),
        TEXT | VARCHAR | BPCHAR | NAME | CHAR | JSON => s.as_bytes().to_vec(),
        // jsonb binary: a version byte, then the text.
        JSONB => [&[1u8][..], s.as_bytes()].concat(),
        BYTEA => bytea(s)?,
        UUID => uuid(s)?,
        DATE => date(s)?.to_be_bytes().to_vec(),
        TIME => time_of_day(s)?.to_be_bytes().to_vec(),
        TIMETZ => {
            let (t, off) = split_offset(s)?;
            let off = off.ok_or(BAD)?;
            let mut v = time_of_day(t)?.to_be_bytes().to_vec();
            // Postgres stores the zone as seconds west of UTC.
            v.extend_from_slice(&(-off).to_be_bytes());
            v
        }
        TIMESTAMP => timestamp(s, false)?.to_be_bytes().to_vec(),
        TIMESTAMPTZ => timestamp(s, true)?.to_be_bytes().to_vec(),
        NUMERIC => numeric(s)?,
        POINT => {
            let v = floats_in(s, 2)?;
            v.iter().flat_map(|f| f.to_be_bytes()).collect()
        }
        BOX => {
            let v = floats_in(s, 4)?;
            v.iter().flat_map(|f| f.to_be_bytes()).collect()
        }
        _ => return Err(BAD),
    })
}

fn float(s: &str) -> Result<f64, &'static str> {
    match s {
        "NaN" => Ok(f64::NAN),
        "Infinity" => Ok(f64::INFINITY),
        "-Infinity" => Ok(f64::NEG_INFINITY),
        _ => s.parse().map_err(|_| BAD),
    }
}

/// `n` floats out of a geometric literal: `(1,2)`, `(3,4),(1,2)`.
fn floats_in(s: &str, n: usize) -> Result<Vec<f64>, &'static str> {
    let v = s
        .split([',', '(', ')'])
        .filter(|p| !p.trim().is_empty())
        .map(|p| float(p.trim()))
        .collect::<Result<Vec<_>, _>>()?;
    (v.len() == n).then_some(v).ok_or(BAD)
}

fn hex(b: u8) -> Result<u8, &'static str> {
    (b as char).to_digit(16).map(|d| d as u8).ok_or(BAD)
}

fn bytea(s: &str) -> Result<Vec<u8>, &'static str> {
    let b = s.as_bytes();
    if let Some(h) = s.strip_prefix("\\x") {
        let h = h.as_bytes();
        if h.len() % 2 != 0 {
            return Err(BAD);
        }
        return h
            .chunks(2)
            .map(|c| Ok(hex(c[0])? << 4 | hex(c[1])?))
            .collect();
    }
    // bytea_output = escape: \\ for a backslash, \ooo octal, else literal.
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
        } else if b.get(i + 1) == Some(&b'\\') {
            out.push(b'\\');
            i += 2;
        } else {
            let o = b.get(i + 1..i + 4).ok_or(BAD)?;
            if !o.iter().all(|c| (b'0'..=b'7').contains(c)) {
                return Err(BAD);
            }
            let v = o.iter().fold(0u16, |a, c| a * 8 + (c - b'0') as u16);
            out.push(u8::try_from(v).map_err(|_| BAD)?);
            i += 4;
        }
    }
    Ok(out)
}

fn uuid(s: &str) -> Result<Vec<u8>, &'static str> {
    let h: Vec<u8> = s.bytes().filter(|&c| c != b'-').collect();
    if h.len() != 32 {
        return Err(BAD);
    }
    h.chunks(2)
        .map(|c| Ok(hex(c[0])? << 4 | hex(c[1])?))
        .collect()
}

/// Days from 2000-01-01 to y-m-d (proleptic Gregorian, astronomical years).
fn days_from_2000(y: i64, m: i64, d: i64) -> i64 {
    // Howard Hinnant's days_from_civil, shifted from 1970 to 2000.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468 - 10_957
}

/// `YYYY-MM-DD[ BC]` -> days since 2000-01-01.
fn date_days(s: &str) -> Result<i64, &'static str> {
    let (s, bc) = match s.strip_suffix(" BC") {
        Some(s) => (s, true),
        None => (s, false),
    };
    let mut it = s.splitn(3, '-');
    let mut next =
        || -> Result<i64, &'static str> { it.next().ok_or(BAD)?.parse::<i64>().map_err(|_| BAD) };
    let (y, m, d) = (next()?, next()?, next()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || y < 1 {
        return Err(BAD);
    }
    // 1 BC is astronomical year 0.
    Ok(days_from_2000(if bc { 1 - y } else { y }, m, d))
}

fn date(s: &str) -> Result<i32, &'static str> {
    match s {
        "infinity" => Ok(i32::MAX),
        "-infinity" => Ok(i32::MIN),
        _ => i32::try_from(date_days(s)?).map_err(|_| BAD),
    }
}

/// `HH:MM:SS[.ffffff]` -> microseconds.
fn time_of_day(s: &str) -> Result<i64, &'static str> {
    let (hms, frac) = s.split_once('.').unwrap_or((s, ""));
    let mut it = hms.splitn(3, ':');
    let mut next =
        || -> Result<i64, &'static str> { it.next().ok_or(BAD)?.parse::<i64>().map_err(|_| BAD) };
    let (h, m, sec) = (next()?, next()?, next()?);
    if frac.len() > 6 || !frac.bytes().all(|c| c.is_ascii_digit()) {
        return Err(BAD);
    }
    let us = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<6}").parse::<i64>().map_err(|_| BAD)?
    };
    Ok(((h * 60 + m) * 60 + sec) * 1_000_000 + us)
}

/// Split a trailing `+HH[:MM[:SS]]` / `-HH...` zone offset (seconds east).
fn split_offset(s: &str) -> Result<(&str, Option<i32>), &'static str> {
    // The offset follows the time; the date's own '-' come first.
    let Some(i) = s.rfind(['+', '-']).filter(|&i| s[..i].contains(':')) else {
        return Ok((s, None));
    };
    let sign = if s.as_bytes()[i] == b'-' { -1 } else { 1 };
    let mut secs = 0i32;
    for (part, unit) in s[i + 1..].split(':').zip([3600, 60, 1]) {
        secs += part.parse::<i32>().map_err(|_| BAD)? * unit;
    }
    Ok((&s[..i], Some(sign * secs)))
}

/// `YYYY-MM-DD HH:MM:SS[.ffffff][+zz][ BC]` -> microseconds since
/// 2000-01-01 00:00 (UTC for timestamptz).
fn timestamp(s: &str, tz: bool) -> Result<i64, &'static str> {
    match s {
        "infinity" => return Ok(i64::MAX),
        "-infinity" => return Ok(i64::MIN),
        _ => {}
    }
    let (s, bc) = match s.strip_suffix(" BC") {
        Some(s) => (s, " BC"),
        None => (s, ""),
    };
    let (d, t) = s.split_once(' ').ok_or(BAD)?;
    let (t, off) = split_offset(t)?;
    if tz != off.is_some() {
        return Err(BAD);
    }
    let days = date_days(&format!("{d}{bc}"))?;
    let us = days * 86_400_000_000 + time_of_day(t)?;
    Ok(us - off.unwrap_or(0) as i64 * 1_000_000)
}

/// Postgres numeric binary: ndigits, weight, sign, dscale, base-10000 digits.
fn numeric(s: &str) -> Result<Vec<u8>, &'static str> {
    let special = |sign: u16| {
        let mut v = vec![0, 0, 0, 0];
        v.extend_from_slice(&sign.to_be_bytes());
        v.extend_from_slice(&[0, 0]);
        v
    };
    match s {
        "NaN" => return Ok(special(0xC000)),
        "Infinity" => return Ok(special(0xD000)),
        "-Infinity" => return Ok(special(0xF000)),
        _ => {}
    }
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    let (int, frac) = s.split_once('.').unwrap_or((s, ""));
    if int.is_empty() || !(int.bytes().chain(frac.bytes())).all(|c| c.is_ascii_digit()) {
        return Err(BAD);
    }
    let dscale = frac.len() as i16;
    // Pad to whole base-10000 groups: int on the left, frac on the right.
    let int = format!("{}{int}", "0".repeat((4 - int.len() % 4) % 4));
    let frac = format!("{frac}{}", "0".repeat((4 - frac.len() % 4) % 4));
    let digits = |t: &str| -> Vec<i16> {
        t.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap().parse().unwrap())
            .collect()
    };
    let mut groups = digits(&int);
    let mut weight = groups.len() as i16 - 1;
    groups.extend(digits(&frac));
    while groups.first() == Some(&0) {
        groups.remove(0);
        weight -= 1;
    }
    while groups.last() == Some(&0) {
        groups.pop();
    }
    if groups.is_empty() {
        weight = 0;
    }
    let sign: u16 = if neg && !groups.is_empty() { 0x4000 } else { 0 };
    let mut v = Vec::with_capacity(8 + groups.len() * 2);
    v.extend_from_slice(&(groups.len() as i16).to_be_bytes());
    v.extend_from_slice(&weight.to_be_bytes());
    v.extend_from_slice(&sign.to_be_bytes());
    v.extend_from_slice(&dscale.to_be_bytes());
    for g in groups {
        v.extend_from_slice(&g.to_be_bytes());
    }
    Ok(v)
}

/// One-dimensional or nested array literal: `{1,2}`, `{{1,2},{3,4}}`,
/// `[0:1]={1,2}`, `{"a,b",NULL,"x\"y"}`.
fn encode_array(elem: i32, s: &str) -> Result<Vec<u8>, &'static str> {
    let (lbounds, body) = match s.split_once('=').filter(|_| s.starts_with('[')) {
        Some((dims, body)) => (
            dims.split(']')
                .filter(|d| !d.is_empty())
                .map(|d| {
                    let lo = d.trim_start_matches('[').split(':').next().ok_or(BAD)?;
                    lo.parse::<i32>().map_err(|_| BAD)
                })
                .collect::<Result<Vec<_>, _>>()?,
            body,
        ),
        None => (Vec::new(), s),
    };
    let mut p = ArrayParser {
        b: body.as_bytes(),
        i: 0,
        dims: Vec::new(),
        elems: Vec::new(),
    };
    p.parse(0)?;
    if p.i != p.b.len() {
        return Err(BAD);
    }
    let dims: Vec<usize> = p.dims.into_iter().collect::<Option<_>>().ok_or(BAD)?;
    let ndim = if p.elems.is_empty() { 0 } else { dims.len() };
    let mut v = Vec::new();
    v.extend_from_slice(&(ndim as i32).to_be_bytes());
    v.extend_from_slice(&(p.elems.iter().any(Option::is_none) as i32).to_be_bytes());
    v.extend_from_slice(&elem.to_be_bytes());
    for (d, len) in dims.iter().take(ndim).enumerate() {
        v.extend_from_slice(&(*len as i32).to_be_bytes());
        v.extend_from_slice(&lbounds.get(d).copied().unwrap_or(1).to_be_bytes());
    }
    for e in p.elems {
        match e {
            None => v.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(t) => {
                let b = encode_scalar(elem, &t)?;
                v.extend_from_slice(&(b.len() as i32).to_be_bytes());
                v.extend_from_slice(&b);
            }
        }
    }
    Ok(v)
}

struct ArrayParser<'a> {
    b: &'a [u8],
    i: usize,
    /// Element count per nesting level, set when that level first closes.
    dims: Vec<Option<usize>>,
    elems: Vec<Option<String>>,
}

impl ArrayParser<'_> {
    fn parse(&mut self, depth: usize) -> Result<(), &'static str> {
        if depth > 6 || self.b.get(self.i) != Some(&b'{') {
            return Err(BAD);
        }
        self.i += 1;
        let mut n = 0;
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return self.dim(depth, 0);
        }
        loop {
            if self.b.get(self.i) == Some(&b'{') {
                self.parse(depth + 1)?;
            } else {
                let e = self.element()?;
                self.elems.push(e);
            }
            n += 1;
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return self.dim(depth, n);
                }
                _ => return Err(BAD),
            }
        }
    }

    /// Record (or check) the length of dimension `depth`.
    fn dim(&mut self, depth: usize, n: usize) -> Result<(), &'static str> {
        if self.dims.len() <= depth {
            self.dims.resize(depth + 1, None);
        }
        match self.dims[depth] {
            Some(d) if d != n => Err(BAD),
            Some(_) => Ok(()),
            None => {
                self.dims[depth] = Some(n);
                Ok(())
            }
        }
    }

    fn element(&mut self) -> Result<Option<String>, &'static str> {
        let mut out = Vec::new();
        if self.b.get(self.i) == Some(&b'"') {
            self.i += 1;
            loop {
                match *self.b.get(self.i).ok_or(BAD)? {
                    b'"' => {
                        self.i += 1;
                        break;
                    }
                    b'\\' => {
                        out.push(*self.b.get(self.i + 1).ok_or(BAD)?);
                        self.i += 2;
                    }
                    c => {
                        out.push(c);
                        self.i += 1;
                    }
                }
            }
            return String::from_utf8(out).map(Some).map_err(|_| BAD);
        }
        while let Some(&c) = self.b.get(self.i) {
            if c == b',' || c == b'}' {
                break;
            }
            out.push(c);
            self.i += 1;
        }
        let t = String::from_utf8(out).map_err(|_| BAD)?;
        Ok((t != "NULL").then_some(t))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(oid: i32, s: &str) -> Vec<u8> {
        encode(oid, s.as_bytes()).unwrap()
    }

    #[test]
    fn scalars() {
        assert_eq!(e(INT4, "-2"), (-2i32).to_be_bytes());
        assert_eq!(e(INT8, "9000000000"), 9_000_000_000i64.to_be_bytes());
        assert_eq!(e(INT2, "7"), 7i16.to_be_bytes());
        assert_eq!(e(BOOL, "t"), [1]);
        assert_eq!(e(FLOAT8, "0.1"), 0.1f64.to_be_bytes());
        assert_eq!(e(FLOAT4, "1.5"), 1.5f32.to_be_bytes());
        assert!(f64::from_be_bytes(e(FLOAT8, "NaN").try_into().unwrap()).is_nan());
        assert_eq!(e(BYTEA, "\\x00ff10"), [0, 0xff, 0x10]);
        assert_eq!(e(BYTEA, "a\\\\b\\001"), [b'a', b'\\', b'b', 1]);
        assert_eq!(
            e(UUID, "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")[..3],
            [0xa0, 0xee, 0xbc]
        );
        assert_eq!(e(POINT, "(1,-2.5)").len(), 16);
    }

    #[test]
    fn dates_and_times() {
        assert_eq!(e(DATE, "2000-01-01"), 0i32.to_be_bytes());
        assert_eq!(e(DATE, "1999-12-31"), (-1i32).to_be_bytes());
        assert_eq!(e(DATE, "2024-03-01"), 8826i32.to_be_bytes());
        assert_eq!(e(DATE, "0001-01-01 BC"), (-730_485i32).to_be_bytes());
        assert_eq!(e(DATE, "infinity"), i32::MAX.to_be_bytes());
        assert_eq!(e(TIME, "01:02:03.5"), 3_723_500_000i64.to_be_bytes());
        assert_eq!(
            e(TIMESTAMP, "2000-01-02 00:00:00.000001"),
            86_400_000_001i64.to_be_bytes()
        );
        // 2000-01-01 05:30 at +05:30 is midnight UTC.
        assert_eq!(
            e(TIMESTAMPTZ, "2000-01-01 05:30:00+05:30"),
            0i64.to_be_bytes()
        );
        assert_eq!(e(TIMESTAMPTZ, "1999-12-31 19:00:00-05"), 0i64.to_be_bytes());
        let mut tz = 0i64.to_be_bytes().to_vec();
        tz.extend_from_slice(&(-3600i32).to_be_bytes());
        assert_eq!(e(TIMETZ, "00:00:00+01"), tz);
        assert!(encode(TIMESTAMP, b"2000-01-01 00:00:00+00").is_err());
    }

    #[test]
    fn numerics() {
        // 12345.678: digits [1, 2345, 6780], weight 1, dscale 3.
        let mut want = vec![];
        for x in [3i16, 1, 0, 3, 1, 2345, 6780] {
            want.extend_from_slice(&x.to_be_bytes());
        }
        assert_eq!(e(NUMERIC, "12345.678"), want);
        let mut want = vec![];
        for x in [1i16, -1, 0x4000u16 as i16, 4, 5] {
            want.extend_from_slice(&x.to_be_bytes());
        }
        assert_eq!(e(NUMERIC, "-0.0005"), want);
        assert_eq!(e(NUMERIC, "0.00"), [0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(e(NUMERIC, "NaN")[4..6], [0xC0, 0]);
    }

    #[test]
    fn arrays() {
        let v = e(1007, "{1,NULL,3}");
        assert_eq!(v[..12], [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 23]);
        assert_eq!(v[12..20], [0, 0, 0, 3, 0, 0, 0, 1]);
        assert_eq!(v[24..28], 1i32.to_be_bytes());
        assert_eq!(v[28..32], (-1i32).to_be_bytes());
        let t = e(1009, r#"{"a,b","x\"y",plain}"#);
        assert!(t.windows(3).any(|w| w == b"a,b") && t.windows(3).any(|w| w == b"x\"y"));
        let m = e(1007, "{{1,2},{3,4}}");
        assert_eq!(m[..4], 2i32.to_be_bytes());
        let lb = e(1007, "[0:1]={5,6}");
        assert_eq!(lb[16..20], 0i32.to_be_bytes());
        assert_eq!(e(1007, "{}")[..4], 0i32.to_be_bytes());
        assert!(encode(1007, b"{{1,2},{3}}").is_err());
        assert!(encode(1007, b"{1,2").is_err());
    }
}

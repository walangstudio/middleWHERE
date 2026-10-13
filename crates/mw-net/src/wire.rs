//! Server -> client packet serialization for COM_QUERY results.
//!
//! Text-protocol result set layout, classic EOF framing (our greeting does not
//! offer CLIENT_DEPRECATE_EOF, which some drivers, e.g. PyMySQL, lack):
//!   1. Column Count packet      lenenc_int(N)
//!   2. N x Column Definition 41 packets
//!   3. EOF packet               0xFE + warnings + status_flags
//!   4. M x Row packets          lenenc_str per value, 0xFB for NULL
//!   5. EOF packet
//!
//! For OK / ERR after a successful auth/command, see mysql_server.rs.

use mysql_async::consts::ColumnType;
use mysql_async::{Column, Row, Value};

use crate::framing::write_lenenc_int;

pub fn column_count_packet(n: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(9);
    write_lenenc_int(&mut p, n);
    p
}

/// Column Definition (Protocol::ColumnDefinition41).
pub fn column_def_packet(c: &Column) -> Vec<u8> {
    let mut p = Vec::with_capacity(64);
    push_lenenc_bytes(&mut p, b"def"); // catalog
    push_lenenc_bytes(&mut p, c.schema_str().as_bytes());
    push_lenenc_bytes(&mut p, c.table_str().as_bytes());
    push_lenenc_bytes(&mut p, c.org_table_str().as_bytes());
    push_lenenc_bytes(&mut p, c.name_str().as_bytes());
    push_lenenc_bytes(&mut p, c.org_name_str().as_bytes());
    write_lenenc_int(&mut p, 0x0c); // length of the fixed-length fields below
    p.extend_from_slice(&c.character_set().to_le_bytes());
    p.extend_from_slice(&c.column_length().to_le_bytes());
    p.push(column_type_to_byte(c.column_type()));
    p.extend_from_slice(&c.flags().bits().to_le_bytes());
    p.push(c.decimals());
    p.extend_from_slice(&[0u8, 0u8]); // reserved
    p
}

/// Single row in the text protocol.
pub fn row_text_packet(row: &Row) -> Vec<u8> {
    let mut p = Vec::with_capacity(64);
    for i in 0..row.len() {
        let v: &Value = row.as_ref(i).expect("index in range");
        match v {
            Value::NULL => p.push(0xFB),
            Value::Bytes(b) => push_lenenc_bytes(&mut p, b),
            Value::Int(n) => push_lenenc_bytes(&mut p, n.to_string().as_bytes()),
            Value::UInt(n) => push_lenenc_bytes(&mut p, n.to_string().as_bytes()),
            Value::Float(f) => push_lenenc_bytes(&mut p, format_float(*f as f64).as_bytes()),
            Value::Double(d) => push_lenenc_bytes(&mut p, format_float(*d).as_bytes()),
            Value::Date(y, mo, d, h, mi, s, us) => {
                let s = if *h == 0 && *mi == 0 && *s == 0 && *us == 0 {
                    format!("{:04}-{:02}-{:02}", y, mo, d)
                } else if *us == 0 {
                    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, mo, d, h, mi, s)
                } else {
                    format!(
                        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
                        y, mo, d, h, mi, s, us
                    )
                };
                push_lenenc_bytes(&mut p, s.as_bytes());
            }
            Value::Time(neg, days, h, mi, s, us) => {
                let total_h = *days * 24 + (*h as u32);
                let sign = if *neg { "-" } else { "" };
                let s = if *us == 0 {
                    format!("{sign}{:02}:{:02}:{:02}", total_h, mi, s)
                } else {
                    format!("{sign}{:02}:{:02}:{:02}.{:06}", total_h, mi, s, us)
                };
                push_lenenc_bytes(&mut p, s.as_bytes());
            }
        }
    }
    p
}

/// Classic EOF packet: ends the column definitions and the rows.
pub fn eof_packet(status: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(5);
    p.push(0xFE);
    p.extend_from_slice(&0u16.to_le_bytes()); // warnings
    p.extend_from_slice(&status.to_le_bytes());
    p
}

fn push_lenenc_bytes(out: &mut Vec<u8>, b: &[u8]) {
    write_lenenc_int(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn format_float(d: f64) -> String {
    if d.is_nan() {
        "NaN".into()
    } else if d.is_infinite() {
        if d.is_sign_negative() {
            "-inf".into()
        } else {
            "inf".into()
        }
    } else if d.fract() == 0.0 && d.abs() < 1e15 {
        format!("{:.0}", d)
    } else {
        format!("{}", d)
    }
}

fn column_type_to_byte(t: ColumnType) -> u8 {
    // ColumnType is repr(u8) in mysql_common.
    t as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::read_lenenc_int;

    #[test]
    fn column_count_small() {
        assert_eq!(column_count_packet(0), vec![0x00]);
        assert_eq!(column_count_packet(1), vec![0x01]);
        assert_eq!(column_count_packet(0xFA), vec![0xFA]);
    }

    #[test]
    fn column_count_lenenc() {
        let p = column_count_packet(0x100);
        let (v, n) = read_lenenc_int(&p).unwrap();
        assert_eq!(v, 0x100);
        assert_eq!(n, p.len());
    }

    #[test]
    fn eof_packet_bytes() {
        assert_eq!(eof_packet(0x0002), [0xFE, 0, 0, 0x02, 0]);
    }

    #[test]
    fn float_formatting() {
        assert_eq!(format_float(1.0), "1");
        assert_eq!(format_float(1.5), "1.5");
        assert_eq!(format_float(-0.25), "-0.25");
        assert!(format_float(f64::NAN).contains("NaN"));
    }
}

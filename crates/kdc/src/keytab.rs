//! MIT krb5 keytab file format (binary, version 2) -- hand-rolled rather
//! than depending on the one existing Rust crate for this (`kerberos_keytab`,
//! AGPL-3.0-only; this project is Apache-2.0, and the format is a small,
//! stable, fixed-layout binary structure not worth a copyleft dependency
//! for). Not governed by an IETF RFC -- verified against the real
//! `klist -k`/`ktutil` tools (`krb5-workstation`) rather than a published
//! spec, since MIT krb5's own source is the closest thing to a spec.
//!
//! Used to hand a service principal's key to another daemon (rocketsmbd,
//! sshd via GSSAPI, etc.) without ever transmitting the plaintext
//! password -- `iron-kdc-ctl` writes these, external services read them.

use std::io::{self, Read, Write};

use iron_crypto::kerberos::Enctype;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("not a keytab file (bad magic)")]
    BadMagic,
    #[error("unsupported keytab format version {0} (only version 2 is written/read)")]
    UnsupportedVersion(u8),
    #[error("unsupported enctype {0}")]
    UnsupportedEnctype(i32),
}

pub struct KeytabEntry {
    pub realm: String,
    pub components: Vec<String>,
    pub name_type: i32,
    pub timestamp: u32,
    pub kvno: u32,
    pub enctype: Enctype,
    pub key: Vec<u8>,
}

fn write_counted_string<W: Write>(w: &mut W, s: &[u8]) -> io::Result<()> {
    w.write_all(&(s.len() as u16).to_be_bytes())?;
    w.write_all(s)
}

fn read_counted_string<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Encodes one entry's body (everything after the 4-byte length prefix).
fn encode_entry_body(entry: &KeytabEntry) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    buf.write_all(&(entry.components.len() as u16).to_be_bytes())?;
    write_counted_string(&mut buf, entry.realm.as_bytes())?;
    for c in &entry.components {
        write_counted_string(&mut buf, c.as_bytes())?;
    }
    buf.write_all(&entry.name_type.to_be_bytes())?;
    buf.write_all(&entry.timestamp.to_be_bytes())?;
    buf.write_all(&[(entry.kvno & 0xFF) as u8])?; // legacy 8-bit vno
    buf.write_all(&(entry.enctype.etype_number() as u16).to_be_bytes())?;
    write_counted_string(&mut buf, &entry.key)?;
    buf.write_all(&entry.kvno.to_be_bytes())?; // 32-bit vno (overrides the 8-bit one when present)
    Ok(buf)
}

fn decode_entry_body(body: &[u8]) -> Result<KeytabEntry, Error> {
    let mut r = body;
    let mut u16_buf = [0u8; 2];
    r.read_exact(&mut u16_buf)?;
    let num_components = u16::from_be_bytes(u16_buf) as usize;
    let realm = String::from_utf8_lossy(&read_counted_string(&mut r)?).into_owned();
    let mut components = Vec::with_capacity(num_components);
    for _ in 0..num_components {
        components.push(String::from_utf8_lossy(&read_counted_string(&mut r)?).into_owned());
    }
    let mut i32_buf = [0u8; 4];
    r.read_exact(&mut i32_buf)?;
    let name_type = i32::from_be_bytes(i32_buf);
    let mut u32_buf = [0u8; 4];
    r.read_exact(&mut u32_buf)?;
    let timestamp = u32::from_be_bytes(u32_buf);
    let mut vno8 = [0u8; 1];
    r.read_exact(&mut vno8)?;
    r.read_exact(&mut u16_buf)?;
    let etype_num = u16::from_be_bytes(u16_buf) as i32;
    let enctype = Enctype::try_from(etype_num).map_err(|_| Error::UnsupportedEnctype(etype_num))?;
    let key = read_counted_string(&mut r)?;
    // Optional trailing 32-bit kvno, if the entry has room for it.
    let kvno = if r.len() >= 4 {
        r.read_exact(&mut u32_buf)?;
        u32::from_be_bytes(u32_buf)
    } else {
        vno8[0] as u32
    };
    Ok(KeytabEntry { realm, components, name_type, timestamp, kvno, enctype, key })
}

/// Writes a version-2 keytab file containing `entries`.
pub fn write<W: Write>(w: &mut W, entries: &[KeytabEntry]) -> Result<(), Error> {
    w.write_all(&[0x05, 0x02])?; // file format: major 5, version 2
    for entry in entries {
        let body = encode_entry_body(entry)?;
        w.write_all(&(body.len() as i32).to_be_bytes())?;
        w.write_all(&body)?;
    }
    Ok(())
}

/// Reads every entry from a version-2 keytab file. Skips "holes"
/// (negative-length entries, used by MIT tools to mark deleted entries
/// without rewriting the whole file).
pub fn read<R: Read>(r: &mut R) -> Result<Vec<KeytabEntry>, Error> {
    let mut magic = [0u8; 2];
    r.read_exact(&mut magic)?;
    if magic[0] != 0x05 {
        return Err(Error::BadMagic);
    }
    if magic[1] != 0x02 {
        return Err(Error::UnsupportedVersion(magic[1]));
    }
    let mut entries = Vec::new();
    let mut len_buf = [0u8; 4];
    loop {
        match r.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let len = i32::from_be_bytes(len_buf);
        if len < 0 {
            // Hole: skip that many bytes (absolute value), no entry.
            let mut sink = vec![0u8; (-len) as usize];
            r.read_exact(&mut sink)?;
            continue;
        }
        let mut body = vec![0u8; len as usize];
        r.read_exact(&mut body)?;
        entries.push(decode_entry_body(&body)?);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> KeytabEntry {
        KeytabEntry {
            realm: "IRON.LO".to_string(),
            components: vec!["host".to_string(), "il1.g8.lo".to_string()],
            name_type: 2, // NT-SRV-INST
            timestamp: 1_700_000_000,
            kvno: 1,
            enctype: Enctype::Aes256CtsHmacSha384_192,
            key: vec![0x42; 32],
        }
    }

    #[test]
    fn write_then_read_roundtrip() {
        let entry = sample_entry();
        let mut buf = Vec::new();
        write(&mut buf, std::slice::from_ref(&entry)).unwrap();
        let read_back = read(&mut &buf[..]).unwrap();
        assert_eq!(read_back.len(), 1);
        let r = &read_back[0];
        assert_eq!(r.realm, entry.realm);
        assert_eq!(r.components, entry.components);
        assert_eq!(r.name_type, entry.name_type);
        assert_eq!(r.timestamp, entry.timestamp);
        assert_eq!(r.kvno, entry.kvno);
        assert_eq!(r.enctype, entry.enctype);
        assert_eq!(r.key, entry.key);
    }

    #[test]
    fn multiple_entries_roundtrip() {
        let mut e2 = sample_entry();
        e2.components = vec!["ldap".to_string(), "il2.g8.lo".to_string()];
        e2.enctype = Enctype::Aes256CtsHmacSha1_96;
        e2.kvno = 3;
        let entries = vec![sample_entry(), e2];
        let mut buf = Vec::new();
        write(&mut buf, &entries).unwrap();
        let read_back = read(&mut &buf[..]).unwrap();
        assert_eq!(read_back.len(), 2);
        assert_eq!(read_back[1].components, vec!["ldap".to_string(), "il2.g8.lo".to_string()]);
        assert_eq!(read_back[1].kvno, 3);
    }

    #[test]
    fn rejects_bad_magic() {
        let buf = vec![0xFFu8; 10];
        assert!(matches!(read(&mut &buf[..]), Err(Error::BadMagic)));
    }
}

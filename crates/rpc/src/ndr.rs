//! Minimal NDR (Network Data Representation) reader/writer -- just the
//! primitives SAMR/LSARPC/NETLOGON's specific operations need (#19), not
//! a general NDR engine. Little-endian only (`NDR_representation =
//! 0x10` -- ASCII/little-endian/IEEE float, ubiquitous on the wire in
//! practice and the only one this server offers).
//!
//! Mirrors `iron-kdc::pac`'s hand-rolled NDR encoder (#18) -- same
//! "conformant array"/pointer-deferral rules, same reliance on
//! cross-checking against [impacket](https://github.com/fortra/impacket)'s
//! independent implementation for anything finicky -- but adds a
//! **reader** half, since a server must decode client-supplied request
//! PDUs, not just encode its own responses.

use iron_partition::Sid;

#[derive(Debug, thiserror::Error)]
pub enum NdrError {
    #[error("unexpected end of NDR data (need {need} more bytes, have {have})")]
    Truncated { need: usize, have: usize },
    #[error("malformed SID in NDR data")]
    BadSid,
    #[error("malformed UTF-16 string in NDR data")]
    BadString,
}

/// A non-null pointer's referent id (fixed-part placeholder). The value
/// is arbitrary to a conformant decoder -- deferred data is matched by
/// encounter order, not by this value.
const FIRST_REFERENT_ID: u32 = 0x0002_0000;

pub struct NdrWriter {
    pub buf: Vec<u8>,
    next_referent_id: u32,
}

impl NdrWriter {
    pub fn new() -> Self {
        NdrWriter { buf: Vec::new(), next_referent_id: FIRST_REFERENT_ID }
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    pub fn pad_to_4(&mut self) {
        while self.buf.len() % 4 != 0 {
            self.buf.push(0);
        }
    }
    /// A fresh non-null referent id.
    pub fn referent_id(&mut self) -> u32 {
        let id = self.next_referent_id;
        self.next_referent_id += 4;
        self.u32(id);
        id
    }
    pub fn null_ptr(&mut self) {
        self.u32(0);
    }

    /// `RPC_UNICODE_STRING`'s fixed part (`Length`, `MaximumLength`, a
    /// pointer to `Buffer`) -- `None`/empty becomes a null pointer.
    /// Returns the string to later pass to `unicode_string_deferred`, if
    /// non-null.
    pub fn unicode_string_header(&mut self, s: Option<&str>) -> Option<String> {
        match s {
            Some(s) if !s.is_empty() => {
                let len = (s.encode_utf16().count() * 2) as u16;
                self.u16(len);
                self.u16(len);
                self.referent_id();
                Some(s.to_string())
            }
            _ => {
                self.u16(0);
                self.u16(0);
                self.null_ptr();
                None
            }
        }
    }

    /// The conformant-and-varying `WCHAR` buffer deferred data for a
    /// non-null `RPC_UNICODE_STRING`.
    pub fn unicode_string_deferred(&mut self, s: &str) {
        let units: Vec<u16> = s.encode_utf16().collect();
        self.u32(units.len() as u32); // MaximumCount
        self.u32(0); // Offset
        self.u32(units.len() as u32); // ActualCount
        for u in units {
            self.u16(u);
        }
        self.pad_to_4();
    }

    /// A SID in its NDR (`RPC_SID`) representation: the trailing
    /// conformant array's `MaximumCount` hoisted to the front of the
    /// structure -- otherwise identical to [`Sid::encode`]'s flat bytes.
    pub fn sid_deferred(&mut self, sid: &Sid) {
        self.u32(sid.sub_authorities().len() as u32);
        self.bytes(&sid.encode());
    }

    /// A 20-byte opaque context handle (`SAMPR_HANDLE`/`LSAPR_HANDLE`) --
    /// flat bytes, no NDR pointer wrapping.
    pub fn handle(&mut self, h: &[u8; 20]) {
        self.bytes(h);
    }
}

impl Default for NdrWriter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct NdrReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> NdrReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        NdrReader { buf, pos: 0 }
    }

    fn need(&self, n: usize) -> Result<(), NdrError> {
        if self.pos + n > self.buf.len() {
            return Err(NdrError::Truncated { need: n, have: self.buf.len().saturating_sub(self.pos) });
        }
        Ok(())
    }

    pub fn u8(&mut self) -> Result<u8, NdrError> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    pub fn u16(&mut self) -> Result<u16, NdrError> {
        self.need(2)?;
        let v = u16::from_le_bytes(self.buf[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Ok(v)
    }
    pub fn u32(&mut self) -> Result<u32, NdrError> {
        self.need(4)?;
        let v = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }
    pub fn u64(&mut self) -> Result<u64, NdrError> {
        self.need(8)?;
        let v = u64::from_le_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], NdrError> {
        self.need(n)?;
        let b = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(b)
    }
    pub fn pad_to_4(&mut self) {
        while self.pos % 4 != 0 && self.pos < self.buf.len() {
            self.pos += 1;
        }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Reads an `RPC_UNICODE_STRING`'s fixed part; returns `(length,
    /// referent_id)` -- caller reads the deferred buffer separately (in
    /// pointer-encounter order, per NDR's deferral rules) if
    /// `referent_id != 0`.
    pub fn unicode_string_header(&mut self) -> Result<(u16, u32), NdrError> {
        let length = self.u16()?;
        let _max_length = self.u16()?;
        let referent = self.u32()?;
        Ok((length, referent))
    }

    /// The conformant-and-varying `WCHAR` buffer deferred data.
    ///
    /// Does **not** consume trailing alignment padding -- found live
    /// (MS-NRPC's `NetrServerAuthenticate3`) that NDR only pads to the
    /// *next field's own* alignment requirement, not unconditionally to
    /// 4 bytes: a `WSTR` immediately followed by a 2-byte field can have
    /// zero padding between them, while one followed by another u32/
    /// conformant-array field needs padding up to a 4-byte boundary.
    /// Callers must call [`Self::pad_to_4`] themselves when (and only
    /// when) the *next* field genuinely needs 4-byte alignment.
    pub fn unicode_string_deferred(&mut self) -> Result<String, NdrError> {
        let max_count = self.u32()? as usize;
        let _offset = self.u32()?;
        let actual_count = self.u32()? as usize;
        let mut units = Vec::with_capacity(actual_count);
        for _ in 0..actual_count {
            units.push(self.u16()?);
        }
        // Any remaining declared-but-unused units between actual_count and
        // max_count (there shouldn't be any for this server's own callers,
        // but a client is free to send max_count > actual_count).
        if max_count > actual_count {
            self.bytes((max_count - actual_count) * 2)?;
        }
        String::from_utf16(&units).map_err(|_| NdrError::BadString)
    }

    /// A directly-embedded `WSTR` (MS-NRPC's `ComputerName`/`AccountName`
    /// parameters, among others) -- the *same* conformant-and-varying
    /// wire shape as [`Self::unicode_string_deferred`], just read at the
    /// point it appears in the fixed part rather than behind a pointer's
    /// deferred data (there's no `RPC_UNICODE_STRING` `Length`/
    /// `MaximumLength`/referent prefix for a plain `WSTR` field -- it
    /// isn't a pointer at all, unlike `LPWSTR`). A distinct name here so
    /// call sites don't read as "the deferred half of a pointer I must
    /// have read a header for," which would be wrong for this shape.
    pub fn embedded_wstr(&mut self) -> Result<String, NdrError> {
        self.unicode_string_deferred()
    }

    /// A SID in its NDR (`RPC_SID`) representation.
    pub fn sid_deferred(&mut self) -> Result<Sid, NdrError> {
        let count = self.u32()? as usize;
        let flat = self.bytes(8 + 4 * count)?;
        Sid::decode(flat).ok_or(NdrError::BadSid)
    }

    /// A 20-byte opaque context handle.
    pub fn handle(&mut self) -> Result<[u8; 20], NdrError> {
        let b = self.bytes(20)?;
        Ok(b.try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_string_roundtrips() {
        let mut w = NdrWriter::new();
        let s = w.unicode_string_header(Some("alice"));
        if let Some(s) = &s {
            w.unicode_string_deferred(s);
        }
        let mut r = NdrReader::new(&w.buf);
        let (len, referent) = r.unicode_string_header().unwrap();
        assert_eq!(len, 10); // 5 chars * 2 bytes
        assert_ne!(referent, 0);
        let decoded = r.unicode_string_deferred().unwrap();
        assert_eq!(decoded, "alice");
    }

    #[test]
    fn empty_unicode_string_is_null_pointer() {
        let mut w = NdrWriter::new();
        let s = w.unicode_string_header(None);
        assert!(s.is_none());
        let mut r = NdrReader::new(&w.buf);
        let (len, referent) = r.unicode_string_header().unwrap();
        assert_eq!(len, 0);
        assert_eq!(referent, 0);
    }

    #[test]
    fn sid_roundtrips_through_ndr() {
        let sid = Sid::new(Sid::NT_AUTHORITY, [21, 1004336348, 1177238915, 682003330]);
        let mut w = NdrWriter::new();
        w.sid_deferred(&sid);
        let mut r = NdrReader::new(&w.buf);
        let decoded = r.sid_deferred().unwrap();
        assert_eq!(decoded, sid);
    }

    #[test]
    fn handle_roundtrips() {
        let h = [7u8; 20];
        let mut w = NdrWriter::new();
        w.handle(&h);
        let mut r = NdrReader::new(&w.buf);
        assert_eq!(r.handle().unwrap(), h);
    }

    #[test]
    fn truncated_read_errors_cleanly() {
        let mut r = NdrReader::new(&[1, 2]);
        assert!(matches!(r.u32(), Err(NdrError::Truncated { .. })));
    }
}

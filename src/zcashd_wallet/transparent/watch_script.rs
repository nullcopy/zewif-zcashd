use anyhow::Result;
use zewif::{Data, Network, Script};

use crate::{parse, parser::prelude::*, zcashd_wallet::u160};

use super::{KeyId, PubKey, ScriptId};

/// Opcodes used by standard Zcash transparent output scripts.
const OP_DUP: u8 = 0x76;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_HASH160: u8 = 0xa9;
const OP_CHECKSIG: u8 = 0xac;
const PUSHBYTES_20: u8 = 0x14;
const PUSHBYTES_33: u8 = 0x21;
const PUSHBYTES_65: u8 = 0x41;

/// Classification of a watch-only `CScript` imported via `importaddress` or
/// `importpubkey`.
///
/// Consumers should match on this enum instead of re-inspecting opcodes; the
/// `Other` variant carries the raw script bytes so the variant alone is
/// self-describing for any non-standard case.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WatchScriptKind {
    /// `<pubkey> OP_CHECKSIG`
    P2PK(PubKey),
    /// `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`
    P2PKH(KeyId),
    /// `OP_HASH160 <20-byte hash> OP_EQUAL`
    P2SH(ScriptId),
    /// A script that does not match any of the standard patterns above; the
    /// payload is the raw script bytes verbatim.
    Other(Data),
}

impl WatchScriptKind {
    /// Attempts to classify the given script bytes into a standard pattern.
    pub fn classify(script: &[u8]) -> Self {
        // P2PKH: 0x76 0xa9 0x14 <20 bytes> 0x88 0xac
        if script.len() == 25
            && script[0] == OP_DUP
            && script[1] == OP_HASH160
            && script[2] == PUSHBYTES_20
            && script[23] == OP_EQUALVERIFY
            && script[24] == OP_CHECKSIG
        {
            if let Ok(hash) = u160::from_slice(&script[3..23]) {
                return WatchScriptKind::P2PKH(KeyId::from(hash));
            }
        }

        // P2SH: 0xa9 0x14 <20 bytes> 0x87
        if script.len() == 23
            && script[0] == OP_HASH160
            && script[1] == PUSHBYTES_20
            && script[22] == OP_EQUAL
        {
            if let Ok(hash) = u160::from_slice(&script[2..22]) {
                return WatchScriptKind::P2SH(ScriptId::from(hash));
            }
        }

        // P2PK (compressed): 0x21 <33 bytes> 0xac, with a SEC1 sign byte of
        // 0x02 or 0x03. Without the sign-byte check, arbitrary 33-byte blobs
        // wrapped in PUSHBYTES_33/OP_CHECKSIG would classify as P2PK even
        // though they cannot be valid compressed pubkeys.
        //
        // PUSHBYTES_33 (0x21) is conveniently also the CompactSize encoding
        // of 33, so `&script[..34]` is `[len][33 pubkey bytes]` — exactly the
        // shape `PubKey::parse_buf` expects.
        if script.len() == 35
            && script[0] == PUSHBYTES_33
            && script[34] == OP_CHECKSIG
            && (script[1] == 0x02 || script[1] == 0x03)
        {
            let buf: &[u8] = &script[..34];
            if let Ok(pubkey) = PubKey::parse_buf(&buf, false) {
                return WatchScriptKind::P2PK(pubkey);
            }
        }

        // P2PK (uncompressed): 0x41 <65 bytes> 0xac, with a SEC1 sign byte
        // of 0x04. As with the compressed case above, PUSHBYTES_65 (0x41) is
        // the CompactSize encoding of 65, so `&script[..66]` is the
        // `[len][65 pubkey bytes]` shape `PubKey::parse_buf` expects.
        if script.len() == 67
            && script[0] == PUSHBYTES_65
            && script[66] == OP_CHECKSIG
            && script[1] == 0x04
        {
            let buf: &[u8] = &script[..66];
            if let Ok(pubkey) = PubKey::parse_buf(&buf, false) {
                return WatchScriptKind::P2PK(pubkey);
            }
        }

        WatchScriptKind::Other(Data::from_slice(script))
    }
}

/// A watch-only transparent output script recorded by `zcashd` under the
/// `watchs` key.
///
/// The raw script is preserved verbatim; `kind` provides a ready-made
/// classification into the standard `P2PK` / `P2PKH` / `P2SH` patterns.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WatchScript {
    script: Script,
    kind: WatchScriptKind,
}

impl WatchScript {
    pub fn new(script: Script) -> Self {
        let kind = WatchScriptKind::classify(script.as_ref());
        Self { script, kind }
    }

    pub fn script(&self) -> &Script {
        &self.script
    }

    pub fn kind(&self) -> &WatchScriptKind {
        &self.kind
    }

    /// If this script corresponds to a standard transparent address pattern,
    /// returns the encoded `t-addr` string for the given network.
    pub fn to_address_string(&self, network: Network) -> Option<String> {
        match &self.kind {
            WatchScriptKind::P2PKH(key_id) => Some(key_id.to_string(network)),
            WatchScriptKind::P2SH(script_id) => Some(script_id.to_string(network)),
            WatchScriptKind::P2PK(_) | WatchScriptKind::Other(_) => None,
        }
    }
}

impl Parse for WatchScript {
    fn parse(p: &mut Parser) -> Result<Self> {
        let script = parse!(p, Script, "watch-only script")?;
        Ok(Self::new(script))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_p2pkh() {
        let mut script = vec![OP_DUP, OP_HASH160, PUSHBYTES_20];
        script.extend_from_slice(&[0xab; 20]);
        script.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
        assert!(matches!(
            WatchScriptKind::classify(&script),
            WatchScriptKind::P2PKH(_)
        ));
    }

    #[test]
    fn classifies_p2sh() {
        let mut script = vec![OP_HASH160, PUSHBYTES_20];
        script.extend_from_slice(&[0xcd; 20]);
        script.push(OP_EQUAL);
        assert!(matches!(
            WatchScriptKind::classify(&script),
            WatchScriptKind::P2SH(_)
        ));
    }

    #[test]
    fn classifies_p2pk_compressed() {
        let mut script = vec![PUSHBYTES_33, 0x02];
        script.extend_from_slice(&[0xee; 32]);
        script.push(OP_CHECKSIG);
        assert!(matches!(
            WatchScriptKind::classify(&script),
            WatchScriptKind::P2PK(_)
        ));
    }

    #[test]
    fn classifies_p2pk_uncompressed() {
        let mut script = vec![PUSHBYTES_65, 0x04];
        script.extend_from_slice(&[0x11; 64]);
        script.push(OP_CHECKSIG);
        assert!(matches!(
            WatchScriptKind::classify(&script),
            WatchScriptKind::P2PK(_)
        ));
    }

    #[test]
    fn p2pk_with_invalid_sign_byte_falls_through_to_other() {
        // Compressed P2PK shape but with a sign byte other than 0x02/0x03.
        let mut compressed = vec![PUSHBYTES_33, 0xff];
        compressed.extend_from_slice(&[0xee; 32]);
        compressed.push(OP_CHECKSIG);
        assert!(matches!(
            WatchScriptKind::classify(&compressed),
            WatchScriptKind::Other(_)
        ));

        // Uncompressed P2PK shape but with a sign byte other than 0x04.
        let mut uncompressed = vec![PUSHBYTES_65, 0xff];
        uncompressed.extend_from_slice(&[0x11; 64]);
        uncompressed.push(OP_CHECKSIG);
        assert!(matches!(
            WatchScriptKind::classify(&uncompressed),
            WatchScriptKind::Other(_)
        ));
    }

    #[test]
    fn classifies_other() {
        let empty = WatchScriptKind::classify(&[]);
        match empty {
            WatchScriptKind::Other(bytes) => {
                let raw: &[u8] = bytes.as_ref();
                assert!(raw.is_empty());
            }
            _ => panic!("expected Other"),
        }

        let short = WatchScriptKind::classify(&[0x00, 0x01, 0x02]);
        match short {
            WatchScriptKind::Other(bytes) => {
                let raw: &[u8] = bytes.as_ref();
                assert_eq!(raw, &[0x00, 0x01, 0x02]);
            }
            _ => panic!("expected Other"),
        }

        // Near-miss P2PKH with wrong last opcode: the variant must still
        // round-trip the input bytes verbatim.
        let mut near_miss = vec![OP_DUP, OP_HASH160, PUSHBYTES_20];
        near_miss.extend_from_slice(&[0x00; 20]);
        near_miss.extend_from_slice(&[OP_EQUALVERIFY, 0x00]);
        let classified = WatchScriptKind::classify(&near_miss);
        match classified {
            WatchScriptKind::Other(bytes) => {
                let raw: &[u8] = bytes.as_ref();
                assert_eq!(raw, near_miss.as_slice());
            }
            _ => panic!("expected Other"),
        }
    }
}

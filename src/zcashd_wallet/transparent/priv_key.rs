use anyhow::{Result, bail};

use zewif::Data;

use crate::{
    parse,
    parser::prelude::*,
    zcashd_wallet::{CompactSize, u256},
};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PrivKey {
    data: Data,
    hash: u256,
}

impl PrivKey {
    pub fn data(&self) -> &Data {
        &self.data
    }

    pub fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn hash(&self) -> u256 {
        self.hash
    }

    /// Extracts the 32-byte secp256k1 scalar from the SEC1 `EC PRIVATE KEY`
    /// DER blob stored by `zcashd`.
    ///
    /// Both the 214-byte (compressed pubkey) and 279-byte (uncompressed pubkey)
    /// encodings carry an `INTEGER 1, OCTET STRING(32) <scalar>` prologue
    /// inside the outer SEQUENCE. This locates that prologue by its byte
    /// pattern (`02 01 01 04 20`) rather than by hardcoded offset, which keeps
    /// the extractor robust to the differing SEQUENCE length encodings.
    pub fn secp256k1_scalar(&self) -> Result<[u8; 32]> {
        const MARKER: &[u8] = &[0x02, 0x01, 0x01, 0x04, 0x20];
        let bytes = self.as_slice();
        let start = bytes
            .windows(MARKER.len())
            .position(|w| w == MARKER)
            .map(|i| i + MARKER.len())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "PrivKey does not contain expected SEC1 EC private key prologue"
                )
            })?;
        if start + 32 > bytes.len() {
            bail!("PrivKey too short to contain a 32-byte secp256k1 scalar");
        }
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&bytes[start..start + 32]);
        Ok(scalar)
    }
}

impl std::fmt::Debug for PrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "PrivKey({:?})", self.data())
    }
}

impl AsRef<Data> for PrivKey {
    fn as_ref(&self) -> &Data {
        self.data()
    }
}

impl AsRef<[u8]> for PrivKey {
    fn as_ref(&self) -> &[u8] {
        self.data().as_ref()
    }
}

impl Parse for PrivKey {
    fn parse(p: &mut Parser) -> Result<Self> {
        let length = *parse!(p, CompactSize, "PrivKey size")?;
        if length != 214 && length != 279 {
            bail!("Invalid PrivKey size: {}", length);
        }
        let data = parse!(p, data = length, "PrivKey")?;
        let hash = parse!(p, "PrivKey hash")?;
        Ok(Self { data, hash })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zewif::Data;

    fn make_compressed_blob(scalar: [u8; 32]) -> Data {
        // 30 81 D3 (SEQ 211) + 02 01 01 (INTEGER 1) + 04 20 <scalar> + filler to 214 bytes
        let mut blob = vec![0x30, 0x81, 0xD3, 0x02, 0x01, 0x01, 0x04, 0x20];
        blob.extend_from_slice(&scalar);
        blob.resize(214, 0xAA);
        Data::from_slice(&blob)
    }

    fn make_uncompressed_blob(scalar: [u8; 32]) -> Data {
        // 30 82 01 13 (SEQ 275) + 02 01 01 (INTEGER 1) + 04 20 <scalar> + filler to 279 bytes
        let mut blob = vec![0x30, 0x82, 0x01, 0x13, 0x02, 0x01, 0x01, 0x04, 0x20];
        blob.extend_from_slice(&scalar);
        blob.resize(279, 0xBB);
        Data::from_slice(&blob)
    }

    #[test]
    fn extracts_scalar_from_compressed_blob() {
        let scalar = [0x42u8; 32];
        let pk = PrivKey {
            data: make_compressed_blob(scalar),
            hash: u256::default(),
        };
        assert_eq!(pk.secp256k1_scalar().unwrap(), scalar);
    }

    #[test]
    fn extracts_scalar_from_uncompressed_blob() {
        let scalar = [0x99u8; 32];
        let pk = PrivKey {
            data: make_uncompressed_blob(scalar),
            hash: u256::default(),
        };
        assert_eq!(pk.secp256k1_scalar().unwrap(), scalar);
    }

    #[test]
    fn rejects_blob_without_marker() {
        let pk = PrivKey {
            data: Data::from_slice(&vec![0u8; 214]),
            hash: u256::default(),
        };
        assert!(pk.secp256k1_scalar().is_err());
    }
}

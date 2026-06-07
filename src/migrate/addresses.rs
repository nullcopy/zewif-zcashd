use anyhow::{Context, Result, anyhow};
use secp256k1::PublicKey;
use std::collections::{HashMap, HashSet};
use zcash_keys::keys::{ReceiverRequirement, UnifiedAddressRequest};
use zcash_transparent::address::TransparentAddress;
use zip32::DiversifierIndex;

use zcash_address::{ToAddress, ZcashAddress};
use zewif::{
    Account, DerivationInfo, NonHardenedChildIndex, ProtocolAddress, Script, UnifiedAddress,
    sapling::{
        SaplingExtendedFullViewingKey, SaplingExtendedSpendingKey, SaplingIncomingViewingKey,
    },
    transparent::{TransparentSpendAuthority, TransparentSpendingKey},
};

use super::keys::find_sapling_key_for_ivk;
use crate::{
    ZcashdWallet,
    migrate::{AddressId, AddressRegistry, primitives::address_network_from_zewif},
    zcashd_wallet::{Address, ReceiverType, UfvkFingerprint, transparent::KeyPair},
};

/// Convert ZCashd transparent addresses to Zewif format
///
/// This function handles transparent address assignment:
/// - If registry is available, tries to map addresses to accounts
/// - Otherwise assigns all addresses to the default account
pub fn convert_transparent_addresses(
    wallet: &ZcashdWallet,
    default_account: &mut zewif::Account,
    address_registry: Option<&AddressRegistry>,
    accounts_map: &mut Option<&mut HashMap<UfvkFingerprint, Account>>,
) -> Result<()> {
    let network = wallet.network();

    let mut merged = MergeMap::default();

    for (zcashd_address, name) in wallet.address_names() {
        let addr_str: String = zcashd_address.clone().into();
        merged.record_name(&addr_str, name);
    }

    for keypair in wallet.keys().keypairs() {
        let pk = PublicKey::from_slice(keypair.pubkey().as_slice())
            .context("parsing transparent public key from keypair")?;
        let TransparentAddress::PublicKeyHash(hash) = TransparentAddress::from_pubkey(&pk) else {
            unreachable!("from_pubkey always returns PublicKeyHash");
        };
        let addr_str =
            ZcashAddress::from_transparent_p2pkh(address_network_from_zewif(network), hash)
                .to_string();
        // Register the address even when no spend info is recoverable, so a
        // later watchs/cscript contribution can still attach to the entry.
        merged.ensure_entry(&addr_str);
        let (spend_authority, derivation_info) = spend_info_for_keypair(keypair);
        if let Some(authority) = spend_authority {
            merged.record_spend_authority(&addr_str, authority);
        }
        if let Some(info) = derivation_info {
            merged.record_derivation_info(&addr_str, info);
        }
    }

    // Watch-only scripts that classify to P2PKH or P2SH have a canonical
    // t-address encoding and are folded into the merge. P2PK and non-standard
    // (`Other`) scripts have no t-address representation, so they cannot be
    // surfaced as addresses on the migrated wallet — the raw scripts remain
    // on the source `ZcashdWallet` but the migration drops them here. Warn
    // so the user knows the import is not round-tripping.
    for watch_script in wallet.watch_scripts() {
        match watch_script.to_address_string(network) {
            Some(addr_str) => {
                merged.ensure_entry(&addr_str);
            }
            None => {
                eprintln!(
                    "warning: watch-only script with no standard t-address encoding ({:?}) will not appear on the migrated wallet",
                    watch_script.kind(),
                );
            }
        }
    }

    // `cscripts` records carry the redeem script for each P2SH address the
    // wallet has registered. The script's `ScriptId` is the hash-160 of the
    // redeem script, which is also exactly the script-hash encoded in the
    // P2SH t-address — so we can key by the encoded address and recover the
    // redeem script for spending.
    for (script_id, script) in wallet.cscripts() {
        let addr_str = script_id.to_string(network);
        merged.record_redeem_script(&addr_str, script.clone());
    }

    // `address_purposes` only annotates existing entries; addresses present
    // *only* in `address_purposes` are intentionally not introduced here.
    // `MergeMap` defers purpose application until `into_entries`, so this
    // loop can run in any order relative to the others without changing the
    // outcome.
    for (addr, purpose) in wallet.address_purposes() {
        let addr_str: String = addr.clone().into();
        merged.record_purpose(&addr_str, purpose);
    }

    // Sort by encoded address so the migrated wallet is reproducible across
    // runs — `MergeMap::into_entries` already returns entries in this order.
    for (addr_str, info) in merged.into_entries() {
        emit_transparent_address(
            default_account,
            address_registry,
            accounts_map,
            addr_str,
            info,
        );
    }

    Ok(())
}

#[derive(Default, Debug)]
struct EmitInfo {
    spend_authority: Option<TransparentSpendAuthority>,
    derivation_info: Option<DerivationInfo>,
    redeem_script: Option<Script>,
    name: Option<String>,
    purpose: Option<String>,
}

/// Accumulator for transparent-address metadata gathered from the four
/// `zcashd` sources (`address_names`, key pairs, `watchs`, `cscript`) plus
/// `address_purposes`. Entries are keyed by the canonical encoded t-address
/// string so contributions from different sources merge cleanly.
///
/// Conflict policy across all `record_*` methods: the first non-`None`
/// contribution wins, and any subsequent contribution that disagrees is
/// reported to stderr and dropped. This keeps the migration output stable
/// against source ordering — see `merge_tests::source_order_does_not_matter`.
///
/// Purposes are deferred: `record_purpose` only stages contributions, and
/// they are folded into matching entries by `into_entries`. This means a
/// purpose recorded before any other contribution for the same address is
/// retained until either an entry appears (and the purpose attaches to it)
/// or finalization runs (and a purpose with no entry is dropped silently).
#[derive(Default)]
struct MergeMap {
    entries: HashMap<String, EmitInfo>,
    pending_purposes: Vec<(String, String)>,
}

impl MergeMap {
    fn ensure_entry(&mut self, addr: &str) -> &mut EmitInfo {
        self.entries.entry(addr.to_string()).or_default()
    }

    fn record_name(&mut self, addr: &str, name: &str) {
        let entry = self.ensure_entry(addr);
        match &entry.name {
            Some(existing) if existing != name => {
                eprintln!(
                    "warning: address {} has conflicting names ({:?} vs {:?}); keeping {:?}",
                    addr, existing, name, existing,
                );
            }
            Some(_) => {}
            None => entry.name = Some(name.to_string()),
        }
    }

    fn record_spend_authority(&mut self, addr: &str, authority: TransparentSpendAuthority) {
        let entry = self.ensure_entry(addr);
        if entry.spend_authority.is_some() {
            eprintln!(
                "warning: address {} has conflicting spend authorities; keeping first",
                addr,
            );
        } else {
            entry.spend_authority = Some(authority);
        }
    }

    fn record_derivation_info(&mut self, addr: &str, info: DerivationInfo) {
        let entry = self.ensure_entry(addr);
        if entry.derivation_info.is_some() {
            eprintln!(
                "warning: address {} has conflicting derivation info; keeping first",
                addr,
            );
        } else {
            entry.derivation_info = Some(info);
        }
    }

    fn record_redeem_script(&mut self, addr: &str, script: Script) {
        let entry = self.ensure_entry(addr);
        match &entry.redeem_script {
            Some(existing) if existing != &script => {
                eprintln!(
                    "warning: address {} has conflicting redeem scripts; keeping first",
                    addr,
                );
            }
            Some(_) => {}
            None => entry.redeem_script = Some(script),
        }
    }

    fn record_purpose(&mut self, addr: &str, purpose: &str) {
        // Stage the purpose for application during `into_entries`. Deferring
        // here means callers can run the address-purposes pass in any order
        // relative to the entry-creating passes without losing annotations.
        self.pending_purposes
            .push((addr.to_string(), purpose.to_string()));
    }

    /// Apply all staged purposes to their matching entries. Purposes whose
    /// address never received an entry-creating contribution are dropped
    /// silently — `address_purposes` is purely an annotation source and
    /// must not introduce addresses on its own.
    fn finalize_purposes(&mut self) {
        for (addr, purpose) in self.pending_purposes.drain(..) {
            let Some(entry) = self.entries.get_mut(&addr) else {
                continue;
            };
            match &entry.purpose {
                Some(existing) if existing != &purpose => {
                    eprintln!(
                        "warning: address {} has conflicting purposes ({:?} vs {:?}); keeping {:?}",
                        addr, existing, purpose, existing,
                    );
                }
                Some(_) => {}
                None => entry.purpose = Some(purpose),
            }
        }
    }

    /// Consume the map and return entries sorted by encoded address.
    fn into_entries(mut self) -> Vec<(String, EmitInfo)> {
        self.finalize_purposes();
        let mut entries: Vec<_> = self.entries.into_iter().collect();
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        entries
    }
}

fn spend_info_for_keypair(
    keypair: &KeyPair,
) -> (Option<TransparentSpendAuthority>, Option<DerivationInfo>) {
    if let Some(hd_path) = keypair.metadata().hd_keypath() {
        let derivation_info = derivation_info_from_keypath(hd_path);
        // Even if we couldn't parse the keypath, the key is HD-derived in
        // origin — record `Derived` so consumers know the spending key is
        // recoverable from the seed rather than missing.
        (Some(TransparentSpendAuthority::Derived), derivation_info)
    } else {
        match keypair.privkey().secp256k1_scalar() {
            Ok(scalar) => (
                Some(TransparentSpendAuthority::SpendingKey(
                    TransparentSpendingKey::new(scalar),
                )),
                None,
            ),
            Err(_) => (None, None),
        }
    }
}

fn derivation_info_from_keypath(keypath: &str) -> Option<DerivationInfo> {
    // Expected non-hardened tail: `.../<change>/<address_index>`.
    let mut parts = keypath.rsplit('/');
    let address_index = parts.next()?.parse::<u32>().ok()?;
    let change = parts.next()?.parse::<u32>().ok()?;
    Some(DerivationInfo::new(
        NonHardenedChildIndex::from(change),
        NonHardenedChildIndex::from(address_index),
    ))
}

fn emit_transparent_address(
    default_account: &mut zewif::Account,
    address_registry: Option<&AddressRegistry>,
    accounts_map: &mut Option<&mut HashMap<UfvkFingerprint, Account>>,
    addr_str: String,
    info: EmitInfo,
) {
    let zcashd_address = Address::from(addr_str.clone());

    let mut transparent_address = zewif::transparent::Address::new(addr_str);
    if let Some(authority) = info.spend_authority {
        transparent_address.set_spend_authority(authority);
    }
    if let Some(derivation) = info.derivation_info {
        transparent_address.set_derivation_info(derivation);
    }
    if let Some(redeem_script) = info.redeem_script {
        transparent_address.set_redeem_script(redeem_script);
    }

    let mut zewif_address = zewif::Address::new(ProtocolAddress::Transparent(transparent_address));

    if let Some(name) = info.name {
        zewif_address.set_name(name);
    }
    if let Some(purpose) = info.purpose {
        zewif_address.set_purpose(purpose);
    }

    if let (Some(registry), Some(accounts)) = (address_registry, accounts_map.as_mut()) {
        let addr_id = AddressId::Transparent(zcashd_address.into());
        if let Some(account_id) = registry.find_account(&addr_id) {
            if let Some(target_account) = accounts.get_mut(account_id) {
                target_account.add_address(zewif_address);
                return;
            }
        }
    }

    // No registry match: route to the default account. This is the correct
    // fallback for imported keys (`importprivkey`) and watch-only entries
    // from `watchs`/`cscript`, which have no unified-account linkage in
    // zcashd's data model. HD-derived keypair addresses are pre-registered
    // by `initialize_address_registry` so they route via the branch above.
    default_account.add_address(zewif_address);
}

/// Convert ZCashd sapling addresses to Zewif format
///
/// This function handles sapling address assignment:
/// - If registry is available, tries to map addresses to accounts
/// - Otherwise assigns all addresses to the default account
pub fn convert_sapling_addresses(
    wallet: &ZcashdWallet,
    default_account: &mut zewif::Account,
    address_registry: Option<&AddressRegistry>,
    accounts_map: &mut Option<&mut HashMap<UfvkFingerprint, Account>>,
) -> Result<()> {
    let extfvks = wallet.sapling_extended_full_viewing_keys();
    let mut emitted_ivks: HashSet<SaplingIncomingViewingKey> = HashSet::new();

    // First pass: addresses that have a `sapzaddr` record. This covers every
    // spend-capable Sapling address plus any view-only address that was
    // imported via `z_importviewingkey` with `addDefaultAddress=true`. When a
    // `sapextfvk` record exists for the same IVK (the addDefaultAddress=true
    // path always writes both), attach the extended FVK here so the emitted
    // address carries it.
    for (sapling_address, viewing_key) in wallet.sapling_z_addresses() {
        let address_str = sapling_address.to_string(wallet.network());

        let mut shielded_address = zewif::sapling::Address::new(address_str.clone());
        shielded_address.set_incoming_viewing_key(viewing_key.to_owned());

        if let Some(sapling_key) = find_sapling_key_for_ivk(wallet, viewing_key) {
            shielded_address.set_spending_key(SaplingExtendedSpendingKey::new(
                sapling_key.extsk().to_bytes(),
            ));
        }

        if let Some(extfvk) = extfvks.get(viewing_key) {
            shielded_address.set_full_viewing_key(extended_fvk_to_zewif(extfvk)?);
        }

        let mut zewif_address =
            zewif::Address::new(ProtocolAddress::Sapling(Box::new(shielded_address)));

        let zcashd_address = Address::from(address_str.clone());
        if let Some(purpose) = wallet.address_purposes().get(&zcashd_address) {
            zewif_address.set_purpose(purpose.clone());
        }

        route_sapling_address(
            default_account,
            address_registry,
            accounts_map,
            &address_str,
            zewif_address,
        );

        emitted_ivks.insert(*viewing_key);
    }

    // Second pass: `sapextfvk` records imported with `addDefaultAddress=false`
    // produce an extended FVK with no companion `sapzaddr` entry. Recover the
    // canonical default address from the extended FVK so the view-only key
    // is still surfaced on the migrated wallet.
    for (ivk, extfvk) in extfvks {
        if !emitted_ivks.insert(*ivk) {
            continue;
        }

        let (_diversifier_index, payment_address) =
            extfvk.to_diversifiable_full_viewing_key().default_address();
        let address_str = ZcashAddress::from_sapling(
            address_network_from_zewif(wallet.network()),
            payment_address.to_bytes(),
        )
        .to_string();

        let mut shielded_address = zewif::sapling::Address::new(address_str.clone());
        shielded_address.set_incoming_viewing_key(*ivk);
        shielded_address.set_full_viewing_key(extended_fvk_to_zewif(extfvk)?);

        let mut zewif_address =
            zewif::Address::new(ProtocolAddress::Sapling(Box::new(shielded_address)));

        let zcashd_address = Address::from(address_str.clone());
        if let Some(purpose) = wallet.address_purposes().get(&zcashd_address) {
            zewif_address.set_purpose(purpose.clone());
        }

        route_sapling_address(
            default_account,
            address_registry,
            accounts_map,
            &address_str,
            zewif_address,
        );
    }

    Ok(())
}

fn extended_fvk_to_zewif(
    extfvk: &::sapling::zip32::ExtendedFullViewingKey,
) -> Result<SaplingExtendedFullViewingKey> {
    let mut bytes = [0u8; 169];
    extfvk
        .write(&mut bytes[..])
        .map_err(|e| anyhow!("Serializing Sapling extended FVK: {}", e))?;
    Ok(SaplingExtendedFullViewingKey::new(bytes))
}

fn route_sapling_address(
    default_account: &mut zewif::Account,
    address_registry: Option<&AddressRegistry>,
    accounts_map: &mut Option<&mut HashMap<UfvkFingerprint, Account>>,
    address_str: &str,
    zewif_address: zewif::Address,
) {
    if let (Some(registry), Some(accounts)) = (address_registry, accounts_map.as_mut()) {
        let addr_id = AddressId::Sapling(address_str.to_string());
        if let Some(account_id) = registry.find_account(&addr_id) {
            if let Some(target_account) = accounts.get_mut(account_id) {
                target_account.add_address(zewif_address);
                return;
            }
        }
    }
    default_account.add_address(zewif_address);
}

/// Convert ZCashd unified addresses to Zewif format
///
/// This function handles unified address extraction and assignment:
/// - Extracts unified addresses from UnifiedAddressMetadata
/// - Preserves diversifier indices and receiver types
/// - Assigns unified addresses to appropriate accounts using the registry
pub fn convert_unified_addresses(
    wallet: &ZcashdWallet,
    default_account: &mut zewif::Account,
    address_registry: Option<&AddressRegistry>,
    accounts_map: &mut Option<&mut HashMap<UfvkFingerprint, Account>>,
) -> Result<()> {
    // Only process if we have unified accounts
    let unified_accounts = wallet.unified_accounts();

    // Multi-account mode is active when we have both a registry and accounts map
    // TODO: figure out why this is being checked
    let multi_account_mode = address_registry.is_some() && accounts_map.is_some();

    // Process unified address metadata entries
    for metadata in &unified_accounts.address_metadata {
        let account = unified_accounts.account_metadata.get(&metadata.key_id);
        let ufvk = unified_accounts
            .full_viewing_keys
            .get(&metadata.key_id)
            .ok_or(anyhow!(
                "No UFVK was found for UFVK fingerprint {}",
                metadata.key_id.to_hex()
            ))?;

        let ua_str = {
            let j = DiversifierIndex::from(<[u8; 11]>::from(metadata.diversifier_index.clone()));
            let require = |present: bool| {
                if present {
                    ReceiverRequirement::Require
                } else {
                    ReceiverRequirement::Omit
                }
            };
            let request = UnifiedAddressRequest::custom(
                require(metadata.receiver_types.contains(&ReceiverType::P2PKH)),
                require(metadata.receiver_types.contains(&ReceiverType::Sapling)),
                require(metadata.receiver_types.contains(&ReceiverType::Orchard)),
            )
            .map_err(|e| {
                anyhow!("Receiver types do not produce a valid Unified address: {e}")
            })?;

            ufvk.address(j, request)?
                .encode(&wallet.network_info().to_address_encoding_network())
        };

        // Construct the unified address with its derivation metadata.
        let unified_address = UnifiedAddress::from_parts(
            ua_str.clone(),
            Some(metadata.diversifier_index.clone()),
            account.map(|a| format!("m/32'/{}'/{}'", a.bip_44_coin_type(), a.zip32_account_id())),
        );

        // Try to find transparent and sapling components for this unified address
        // from already processed addresses in the wallet

        // Create a unified address protocol address
        let zewif_address =
            zewif::Address::new(ProtocolAddress::Unified(Box::new(unified_address)));

        // Set purpose if available - though we may not have explicit purposes for unified addresses
        // in current wallet structure, this is here for future compatibility

        // In multi-account mode, try to assign to the correct account
        let mut assigned = false;

        if multi_account_mode {
            let registry = address_registry.unwrap();
            let addr_id = AddressId::Unified(ua_str[0..20].to_string());

            if let Some(account_id) = registry.find_account(&addr_id) {
                if let Some(accounts) = accounts_map.as_mut() {
                    if let Some(target_account) = accounts.get_mut(account_id) {
                        // Add to the specified account
                        target_account.add_address(zewif_address.clone());
                        assigned = true;
                    }
                }
            } else {
                // Try with the Unified variant if UnifiedAccountAddress didn't work
                let addr_id = AddressId::Unified(ua_str);
                if let Some(account_id) = registry.find_account(&addr_id) {
                    if let Some(accounts) = accounts_map.as_mut() {
                        if let Some(target_account) = accounts.get_mut(account_id) {
                            // Add to the specified account
                            target_account.add_address(zewif_address.clone());
                            assigned = true;
                        }
                    }
                }
            }
        }

        // If not assigned to an account or in single-account mode, add to default account
        if !assigned {
            default_account.add_address(zewif_address);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_fvk_to_zewif_round_trips_through_parse() {
        // `extended_fvk_to_zewif` serializes a parsed extended FVK into the
        // 169-byte canonical form. Verify directly that the produced bytes
        // parse back to the same extended FVK — the only behavior under
        // test here, independent of any higher-level parser plumbing.
        use ::sapling::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};

        let xsk = ExtendedSpendingKey::master(b"extended_fvk_to_zewif test seed");
        #[allow(deprecated)]
        let original_efvk = xsk.to_extended_full_viewing_key();

        let zewif_efvk = extended_fvk_to_zewif(&original_efvk).unwrap();

        let mut canonical = Vec::new();
        original_efvk.write(&mut canonical).unwrap();
        assert_eq!(zewif_efvk.as_ref(), canonical.as_slice());
        assert_eq!(zewif_efvk.as_ref().len(), 169);

        let bytes: Vec<u8> = zewif_efvk.as_ref().to_vec();
        let reparsed: ExtendedFullViewingKey =
            crate::parse!(buf = &bytes, ExtendedFullViewingKey, "round-trip").unwrap();
        let mut reparsed_bytes = Vec::new();
        reparsed.write(&mut reparsed_bytes).unwrap();
        assert_eq!(reparsed_bytes, canonical);
    }

    #[test]
    fn keypath_parses_canonical_bip44_path() {
        let info = derivation_info_from_keypath("m/44'/133'/0'/0/5").unwrap();
        assert_eq!(u32::from(info.change()), 0);
        assert_eq!(u32::from(info.address_index()), 5);
    }

    #[test]
    fn keypath_parses_change_chain() {
        let info = derivation_info_from_keypath("m/44'/133'/0'/1/12").unwrap();
        assert_eq!(u32::from(info.change()), 1);
        assert_eq!(u32::from(info.address_index()), 12);
    }

    #[test]
    fn keypath_rejects_hardened_tail() {
        // A hardened component carries the `'` suffix, which `parse::<u32>()`
        // will not accept. Only fully non-hardened tails are valid here.
        assert!(derivation_info_from_keypath("m/44'/133'/0'/0'/5'").is_none());
        assert!(derivation_info_from_keypath("m/44'/133'/0'/0/5'").is_none());
        assert!(derivation_info_from_keypath("m/44'/133'/0'/0'/5").is_none());
    }

    #[test]
    fn keypath_rejects_too_few_components() {
        assert!(derivation_info_from_keypath("").is_none());
        assert!(derivation_info_from_keypath("5").is_none());
    }

    #[test]
    fn keypath_rejects_non_numeric_segment() {
        assert!(derivation_info_from_keypath("m/44'/133'/0'/foo/5").is_none());
        assert!(derivation_info_from_keypath("m/44'/133'/0'/0/bar").is_none());
    }

    #[test]
    fn keypath_accepts_bare_change_and_index() {
        // The function only inspects the trailing two segments, so a minimal
        // `<change>/<index>` is sufficient even without the hardened prefix.
        let info = derivation_info_from_keypath("0/7").unwrap();
        assert_eq!(u32::from(info.change()), 0);
        assert_eq!(u32::from(info.address_index()), 7);
    }

    mod merge_tests {
        use super::*;

        const ADDR: &str = "t1example";

        fn make_script(bytes: &[u8]) -> Script {
            Script::from(zewif::Data::from_slice(bytes))
        }

        fn derivation(change: u32, index: u32) -> DerivationInfo {
            DerivationInfo::new(
                NonHardenedChildIndex::from(change),
                NonHardenedChildIndex::from(index),
            )
        }

        #[test]
        fn contributions_from_all_sources_combine_on_same_address() {
            let mut m = MergeMap::default();
            m.record_name(ADDR, "alice");
            m.record_spend_authority(ADDR, TransparentSpendAuthority::Derived);
            m.record_derivation_info(ADDR, derivation(0, 5));
            m.ensure_entry(ADDR);
            m.record_redeem_script(ADDR, make_script(&[0xa9, 0x14]));
            m.record_purpose(ADDR, "receive");
            m.finalize_purposes();

            let info = &m.entries[ADDR];
            assert_eq!(info.name.as_deref(), Some("alice"));
            assert_eq!(info.purpose.as_deref(), Some("receive"));
            assert!(info.redeem_script.is_some());
            assert!(matches!(
                info.spend_authority,
                Some(TransparentSpendAuthority::Derived)
            ));
            assert!(info.derivation_info.is_some());
        }

        #[test]
        fn source_order_does_not_matter() {
            // Build two maps with the same five contributions in opposite
            // orders. With deferred purposes, the early `record_purpose` in
            // `b` no longer needs a replay — `into_entries` (and the
            // `finalize_purposes` it calls) folds it in regardless of when
            // it arrived. The resulting entries must be field-by-field
            // equal.
            let mut a = MergeMap::default();
            a.record_name(ADDR, "alice");
            a.record_spend_authority(ADDR, TransparentSpendAuthority::Derived);
            a.record_derivation_info(ADDR, derivation(0, 5));
            a.record_redeem_script(ADDR, make_script(&[0xab]));
            a.record_purpose(ADDR, "receive");

            let mut b = MergeMap::default();
            b.record_purpose(ADDR, "receive"); // staged, applied at finalize
            b.record_redeem_script(ADDR, make_script(&[0xab]));
            b.record_spend_authority(ADDR, TransparentSpendAuthority::Derived);
            b.record_derivation_info(ADDR, derivation(0, 5));
            b.record_name(ADDR, "alice");

            a.finalize_purposes();
            b.finalize_purposes();
            let ea = &a.entries[ADDR];
            let eb = &b.entries[ADDR];
            assert_eq!(ea.name, eb.name);
            assert_eq!(ea.purpose, eb.purpose);
            assert_eq!(ea.derivation_info, eb.derivation_info);
            assert_eq!(
                ea.redeem_script.as_ref().map(|s| s.as_ref().to_vec()),
                eb.redeem_script.as_ref().map(|s| s.as_ref().to_vec()),
            );
        }

        #[test]
        fn conflicting_names_keep_first() {
            let mut m = MergeMap::default();
            m.record_name(ADDR, "alice");
            m.record_name(ADDR, "bob");
            assert_eq!(m.entries[ADDR].name.as_deref(), Some("alice"));
        }

        #[test]
        fn repeated_identical_name_is_not_a_conflict() {
            let mut m = MergeMap::default();
            m.record_name(ADDR, "alice");
            m.record_name(ADDR, "alice");
            assert_eq!(m.entries[ADDR].name.as_deref(), Some("alice"));
        }

        #[test]
        fn conflicting_spend_authorities_keep_first() {
            let mut m = MergeMap::default();
            m.record_spend_authority(ADDR, TransparentSpendAuthority::Derived);
            m.record_spend_authority(
                ADDR,
                TransparentSpendAuthority::SpendingKey(TransparentSpendingKey::new([0x42; 32])),
            );
            assert!(matches!(
                m.entries[ADDR].spend_authority,
                Some(TransparentSpendAuthority::Derived)
            ));
        }

        #[test]
        fn conflicting_derivation_info_keeps_first() {
            let mut m = MergeMap::default();
            m.record_derivation_info(ADDR, derivation(0, 5));
            m.record_derivation_info(ADDR, derivation(1, 9));
            let d = m.entries[ADDR].derivation_info.as_ref().unwrap();
            assert_eq!(u32::from(d.change()), 0);
            assert_eq!(u32::from(d.address_index()), 5);
        }

        #[test]
        fn ensure_entry_creates_empty_entry() {
            // A keypair whose privkey couldn't be decoded contributes neither
            // a spend authority nor derivation info. The address should still
            // appear in the merged set (via `ensure_entry` at the call site)
            // so that any later watchs/cscript contribution attaches to the
            // same entry.
            let mut m = MergeMap::default();
            m.ensure_entry(ADDR);
            assert!(m.entries.contains_key(ADDR));
            assert!(m.entries[ADDR].spend_authority.is_none());
            assert!(m.entries[ADDR].derivation_info.is_none());
        }

        #[test]
        fn conflicting_redeem_scripts_keep_first() {
            let mut m = MergeMap::default();
            m.record_redeem_script(ADDR, make_script(&[0xa9, 0x14, 0x01]));
            m.record_redeem_script(ADDR, make_script(&[0xa9, 0x14, 0x02]));
            assert_eq!(
                m.entries[ADDR].redeem_script.as_ref().unwrap().as_ref(),
                &[0xa9, 0x14, 0x01][..],
            );
        }

        #[test]
        fn repeated_identical_redeem_script_is_not_a_conflict() {
            let mut m = MergeMap::default();
            m.record_redeem_script(ADDR, make_script(&[0xa9, 0x14, 0xff]));
            m.record_redeem_script(ADDR, make_script(&[0xa9, 0x14, 0xff]));
            assert_eq!(
                m.entries[ADDR].redeem_script.as_ref().unwrap().as_ref(),
                &[0xa9, 0x14, 0xff][..],
            );
        }

        #[test]
        fn redeem_script_and_watch_entry_share_address() {
            let mut m = MergeMap::default();
            m.ensure_entry(ADDR);
            m.record_redeem_script(ADDR, make_script(&[0xa9, 0x14, 0xff]));
            assert!(m.entries[ADDR].redeem_script.is_some());
            // ensure_entry called after record_redeem_script must not clobber.
            m.ensure_entry(ADDR);
            assert!(m.entries[ADDR].redeem_script.is_some());
        }

        #[test]
        fn purpose_without_existing_entry_is_dropped() {
            // A purpose with no entry-creating contribution is staged but
            // never materializes as an entry — `into_entries` returns
            // nothing.
            let mut m = MergeMap::default();
            m.record_purpose(ADDR, "receive");
            assert!(m.into_entries().is_empty());
        }

        #[test]
        fn conflicting_purposes_keep_first() {
            let mut m = MergeMap::default();
            m.record_name(ADDR, "alice");
            m.record_purpose(ADDR, "receive");
            m.record_purpose(ADDR, "send");
            m.finalize_purposes();
            assert_eq!(m.entries[ADDR].purpose.as_deref(), Some("receive"));
        }

        #[test]
        fn into_entries_returns_sorted_by_address() {
            // `convert_transparent_addresses` relies on `into_entries`
            // returning addresses in a deterministic order so the migrated
            // wallet is reproducible across runs.
            let mut m = MergeMap::default();
            m.ensure_entry("t1zzz");
            m.ensure_entry("t1aaa");
            m.ensure_entry("t1mmm");
            let addrs: Vec<String> = m.into_entries().into_iter().map(|(a, _)| a).collect();
            assert_eq!(addrs, vec!["t1aaa", "t1mmm", "t1zzz"]);
        }
    }
}

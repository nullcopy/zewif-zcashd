use anyhow::{Result, anyhow};
use std::collections::HashMap;
use zcash_keys::keys::UnifiedAddressRequest;
use zip32::DiversifierIndex;

use zcash_address::{ToAddress, ZcashAddress};
use zewif::{
    Account, DerivationInfo, NonHardenedChildIndex, ProtocolAddress, UnifiedAddress,
    sapling::{SaplingExtendedSpendingKey, SaplingIncomingViewingKey},
    transparent::{TransparentSpendAuthority, TransparentSpendingKey},
};

use super::keys::find_sapling_key_for_ivk;
use crate::{
    ZcashdWallet,
    migrate::{AddressId, AddressRegistry, primitives::address_network_from_zewif},
    zcashd_wallet::{
        Address, ReceiverType, UfvkFingerprint,
        transparent::{KeyPair, WatchScriptKind},
    },
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
    // Flag for multi-account mode
    let multi_account_mode = address_registry.is_some() && accounts_map.is_some();
    let network = wallet.network();

    // Merge contributions from each source by address string, so that an
    // address appearing in more than one source picks up every available
    // piece of metadata regardless of source ordering.
    let mut merged: HashMap<String, EmitInfo> = HashMap::new();

    for (zcashd_address, name) in wallet.address_names() {
        let addr_str: String = zcashd_address.clone().into();
        let entry = merged.entry(addr_str.clone()).or_default();
        if let Some(existing) = &entry.name {
            if existing != name {
                eprintln!(
                    "warning: address {} has conflicting names ({:?} vs {:?}); keeping {:?}",
                    addr_str, existing, name, existing,
                );
            }
        } else {
            entry.name = Some(name.clone());
        }
    }

    for keypair in wallet.keys().keypairs() {
        let addr_str = keypair.pubkey().key_id().to_string(network);
        let (spend_authority, derivation_info) = spend_info_for_keypair(keypair);
        let entry = merged.entry(addr_str.clone()).or_default();
        if spend_authority.is_some() {
            if entry.spend_authority.is_some() {
                eprintln!(
                    "warning: address {} already has a spend authority; ignoring keypair contribution",
                    addr_str,
                );
            } else {
                entry.spend_authority = spend_authority;
            }
        }
        if derivation_info.is_some() {
            if entry.derivation_info.is_some() {
                eprintln!(
                    "warning: address {} already has derivation info; ignoring keypair contribution",
                    addr_str,
                );
            } else {
                entry.derivation_info = derivation_info;
            }
        }
    }

    for watch_script in wallet.watch_scripts() {
        let addr_str = match watch_script.kind() {
            WatchScriptKind::P2PKH(key_id) => key_id.to_string(network),
            WatchScriptKind::P2SH(script_id) => script_id.to_string(network),
            WatchScriptKind::P2PK(_) | WatchScriptKind::Other => continue,
        };
        merged.entry(addr_str).or_default();
    }

    // address_purposes is keyed by address and applies to entries from any
    // source, so apply it as a final pass over the merged set.
    for (addr_str, info) in merged.iter_mut() {
        let zcashd_address = Address::from(addr_str.clone());
        if let Some(purpose) = wallet.address_purposes().get(&zcashd_address) {
            if let Some(existing) = &info.purpose {
                if existing != purpose {
                    eprintln!(
                        "warning: address {} has conflicting purposes ({:?} vs {:?}); keeping {:?}",
                        addr_str, existing, purpose, existing,
                    );
                }
            } else {
                info.purpose = Some(purpose.clone());
            }
        }
    }

    for (addr_str, info) in merged {
        emit_transparent_address(
            default_account,
            address_registry,
            accounts_map,
            multi_account_mode,
            addr_str,
            info,
        );
    }

    Ok(())
}

#[derive(Default)]
struct EmitInfo {
    spend_authority: Option<TransparentSpendAuthority>,
    derivation_info: Option<DerivationInfo>,
    name: Option<String>,
    purpose: Option<String>,
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
    multi_account_mode: bool,
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

    let mut zewif_address = zewif::Address::new(ProtocolAddress::Transparent(transparent_address));

    if let Some(name) = info.name {
        zewif_address.set_name(name);
    }
    if let Some(purpose) = info.purpose {
        zewif_address.set_purpose(purpose);
    }

    let mut assigned = false;
    if multi_account_mode {
        let registry = address_registry.unwrap();
        let addr_id = AddressId::Transparent(zcashd_address.into());
        if let Some(account_id) = registry.find_account(&addr_id) {
            if let Some(accounts) = accounts_map.as_mut() {
                if let Some(target_account) = accounts.get_mut(account_id) {
                    target_account.add_address(zewif_address.clone());
                    assigned = true;
                }
            }
        }
    }

    if !assigned {
        default_account.add_address(zewif_address);
    }
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
    let multi_account_mode = address_registry.is_some() && accounts_map.is_some();
    let mut emitted_ivks: HashSet<SaplingIncomingViewingKey> = HashSet::new();

    // First pass: addresses that have a `sapzaddr` record. This covers every
    // spend-capable Sapling address plus any view-only address that was
    // imported via `z_importviewingkey` with `addDefaultAddress=true`.
    for (sapling_address, viewing_key) in wallet.sapling_z_addresses() {
        let address_str = sapling_address.to_string(wallet.network());

        let mut shielded_address = zewif::sapling::Address::new(address_str.clone());
        shielded_address.set_incoming_viewing_key(viewing_key.to_owned());

        if let Some(sapling_key) = find_sapling_key_for_ivk(wallet, viewing_key) {
            shielded_address.set_spending_key(SaplingExtendedSpendingKey::new(
                sapling_key.extsk().to_bytes(),
            ));
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
            multi_account_mode,
            &address_str,
            zewif_address,
        );

        emitted_ivks.insert(*viewing_key);
    }

    // Second pass: `sapextfvk` records imported with `addDefaultAddress=false`
    // produce an EFVK with no companion `sapzaddr` entry. Recover the
    // canonical default address from the EFVK so the view-only key is still
    // surfaced on the migrated wallet.
    for (ivk, extfvk) in wallet.sapling_extended_full_viewing_keys() {
        if !emitted_ivks.insert(*ivk) {
            continue;
        }

        let (_diversifier_index, payment_address) = extfvk
            .to_diversifiable_full_viewing_key()
            .default_address();
        let address_str = ZcashAddress::from_sapling(
            address_network_from_zewif(wallet.network()),
            payment_address.to_bytes(),
        )
        .to_string();

        let mut shielded_address = zewif::sapling::Address::new(address_str.clone());
        shielded_address.set_incoming_viewing_key(*ivk);

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
            multi_account_mode,
            &address_str,
            zewif_address,
        );
    }

    Ok(())
}

fn route_sapling_address(
    default_account: &mut zewif::Account,
    address_registry: Option<&AddressRegistry>,
    accounts_map: &mut Option<&mut HashMap<UfvkFingerprint, Account>>,
    multi_account_mode: bool,
    address_str: &str,
    zewif_address: zewif::Address,
) {
    if multi_account_mode {
        let registry = address_registry.unwrap();
        let addr_id = AddressId::Sapling(address_str.to_string());
        if let Some(account_id) = registry.find_account(&addr_id) {
            if let Some(accounts) = accounts_map.as_mut() {
                if let Some(target_account) = accounts.get_mut(account_id) {
                    target_account.add_address(zewif_address);
                    return;
                }
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
            let request = UnifiedAddressRequest::new(
                metadata.receiver_types.contains(&ReceiverType::P2PKH),
                metadata.receiver_types.contains(&ReceiverType::Sapling),
                metadata.receiver_types.contains(&ReceiverType::Orchard),
            )
            .ok_or(anyhow!(
                "Receiver types do not produce a valid Unified address."
            ))?;

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

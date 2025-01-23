use crate::default_vtxo::DefaultVtxo;
use crate::tx_weight_estimator;
use crate::tx_weight_estimator::compute_redeem_tx_fee;
use crate::ArkAddress;
use crate::Error;
use crate::ErrorContext;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot;
use bitcoin::transaction;
use bitcoin::Amount;
use bitcoin::FeeRate;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::TapLeafHash;
use bitcoin::TapSighashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use std::collections::BTreeMap;

/// A VTXO to be spent into an unconfirmed VTXO.
#[derive(Debug, Clone)]
pub struct VtxoInput {
    /// The information needed to spend the VTXO, besides the amount.
    ///
    /// TODO: Eventually we will support VTXOs beyond [`DefaultVtxo`].
    vtxo: DefaultVtxo,
    /// The amount of coins locked in the VTXO.
    amount: Amount,
    /// Where the VTXO would end up on the blockchain if it were to become a UTXO.
    outpoint: OutPoint,
}

impl VtxoInput {
    pub fn new(vtxo: DefaultVtxo, amount: Amount, outpoint: OutPoint) -> Self {
        Self {
            vtxo,
            amount,
            outpoint,
        }
    }
}

/// Build and sign a transaction to send VTXOs to another [`ArkAddress`].
///
/// The inputs will be signed using the forfeit (multisignature) branch of the Taproot tree. Thus,
/// the inputs will still need a signature from the Ark server.
pub fn create_and_sign_redeem_transaction(
    kp: &Keypair,
    to_address: ArkAddress,
    to_amount: Amount,
    change_address: ArkAddress,
    vtxo_inputs: &[VtxoInput],
) -> Result<Psbt, Error> {
    if vtxo_inputs.is_empty() {
        return Err(Error::transaction(
            "cannot create redeem transaction without inputs",
        ));
    }

    let secp = Secp256k1::new();

    let mut outputs = vec![TxOut {
        value: to_amount,
        script_pubkey: to_address.to_p2tr_script_pubkey(),
    }];

    let total_amount: Amount = vtxo_inputs.iter().map(|v| v.amount).sum();

    let change_amount = total_amount.checked_sub(to_amount).ok_or_else(|| {
        Error::transaction(format!(
            "cannot cover to_amount ({to_amount}) with total input amount ({total_amount})"
        ))
    })?;

    if change_amount > Amount::ZERO {
        outputs.push(TxOut {
            value: change_amount,
            script_pubkey: change_address.to_p2tr_script_pubkey(),
        })
    }

    let fee = {
        let vtxos = vtxo_inputs
            .iter()
            .map(
                |VtxoInput {
                     vtxo,
                     amount,
                     outpoint,
                 }| {
                    let (script, control_block) = vtxo.forfeit_spend_info();

                    tx_weight_estimator::VtxoInput {
                        outpoint: *outpoint,
                        amount: *amount,
                        revealed_script: Some(script),
                        control_block,
                        witness_size: DefaultVtxo::FORFEIT_WITNESS_SIZE,
                    }
                },
            )
            .collect::<Vec<_>>();

        compute_redeem_tx_fee(
            FeeRate::from_sat_per_kwu(253),
            vtxos.as_slice(),
            outputs.len(),
        )
        .map_err(Error::from)?
    };

    if let Some(change) = outputs.last_mut() {
        let change_amount = change.value;

        change.value = change_amount.checked_sub(fee).ok_or_else(|| {
            Error::coin_select("fee ({fee}) greater than change ({change_amount})")
        })?;
    };

    // TODO: Use a different locktime if we have CLTV multisig script.
    let lock_time = LockTime::ZERO;

    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time,
        input: vtxo_inputs
            .iter()
            .map(|VtxoInput { outpoint, .. }| TxIn {
                previous_output: *outpoint,
                script_sig: Default::default(),
                // TODO: Use a different sequence number if we have a CLTV multisig script.
                sequence: bitcoin::Sequence::MAX,
                witness: Default::default(),
            })
            .collect(),
        output: outputs,
    };
    let unsigned_psbt = Psbt::from_unsigned_tx(unsigned_tx).map_err(Error::transaction)?;
    let mut signed_redeem_psbt = unsigned_psbt;

    let prevouts = vtxo_inputs
        .iter()
        .map(|VtxoInput { vtxo, amount, .. }| TxOut {
            value: *amount,
            script_pubkey: vtxo.script_pubkey(),
        })
        .collect::<Vec<_>>();

    // Sign all redeem transaction inputs (could be multiple VTXOs!).
    for VtxoInput {
        vtxo,
        amount,
        outpoint,
    } in vtxo_inputs.iter()
    {
        tracing::debug!(
            ?outpoint,
            %amount,
            ?vtxo,
            "Attempting to sign selected VTXO for redeem transaction"
        );

        for (i, psbt_input) in signed_redeem_psbt.inputs.iter_mut().enumerate() {
            let psbt_input_outpoint = signed_redeem_psbt.unsigned_tx.input[i].previous_output;

            if psbt_input_outpoint == *outpoint {
                tracing::debug!(
                    ?outpoint,
                    ?vtxo,
                    index = i,
                    "Signing selected VTXO for redeem transaction"
                );

                psbt_input.witness_utxo = Some(prevouts[i].clone());

                // In the case of input VTXOs, we are actually using a script spend path.
                let (forfeit_script, forfeit_control_block) = vtxo.forfeit_spend_info();

                let leaf_version = forfeit_control_block.leaf_version;
                psbt_input.tap_scripts = BTreeMap::from_iter([(
                    forfeit_control_block,
                    (forfeit_script.clone(), leaf_version),
                )]);

                let prevouts = Prevouts::All(&prevouts);

                let leaf_hash = TapLeafHash::from_script(&forfeit_script, leaf_version);

                let tap_sighash = SighashCache::new(&signed_redeem_psbt.unsigned_tx)
                    .taproot_script_spend_signature_hash(
                        i,
                        &prevouts,
                        leaf_hash,
                        TapSighashType::Default,
                    )
                    .map_err(Error::crypto)
                    .context("failed to generate sighash")?;

                let msg =
                    secp256k1::Message::from_digest(tap_sighash.to_raw_hash().to_byte_array());

                let sig = secp.sign_schnorr_no_aux_rand(&msg, kp);
                let pk = kp.x_only_public_key().0;

                secp.verify_schnorr(&sig, &msg, &pk)
                    .map_err(Error::crypto)
                    .context("failed to verify own redeem signature")?;

                let sig = taproot::Signature {
                    signature: sig,
                    sighash_type: TapSighashType::Default,
                };

                psbt_input.tap_script_sigs = BTreeMap::from_iter([((pk, leaf_hash), sig)]);
            }
        }
    }

    Ok(signed_redeem_psbt)
}

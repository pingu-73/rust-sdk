use crate::asp::VtxoOutPoint;
use crate::boarding_output::BoardingOutput;
use crate::default_vtxo::DefaultVtxo;
use crate::error::Error;
use crate::wallet::BoardingWallet;
use crate::wallet::OnchainWallet;
use crate::Blockchain;
use crate::Client;
use crate::ExplorerUtxo;
use bitcoin::Amount;
use bitcoin::OutPoint;
use std::time::Duration;

/// Select VTXOs to be used as inputs in Out-Of-Round transactions.
pub fn coin_select_for_oor(
    mut vtxo_outpoints: Vec<VtxoOutPoint>,
    amount: Amount,
    dust: Amount,
    sort_by_expiration_time: bool,
) -> Result<(Vec<VtxoOutPoint>, Amount), Error> {
    let mut selected = Vec::new();
    let mut not_selected = Vec::new();
    let mut selected_amount = Amount::ZERO;

    if sort_by_expiration_time {
        // Sort vtxos by expiration (older first)
        vtxo_outpoints.sort_by(|a, b| a.expire_at.cmp(&b.expire_at));
    }

    // Process VTXOs
    for vtxo_outpoint in vtxo_outpoints {
        if selected_amount >= amount {
            not_selected.push(vtxo_outpoint);
        } else {
            selected.push(vtxo_outpoint.clone());
            selected_amount += vtxo_outpoint.amount;
        }
    }

    if selected_amount < amount {
        return Err(Error::coin_select(format!(
            "insufficient funds: selected = {selected_amount}, needed = {amount}"
        )));
    }

    let mut change = selected_amount - amount;

    // Try to avoid generating dust.
    if change < dust {
        if let Some(vtxo) = not_selected.first() {
            selected.push(vtxo.clone());
            change += vtxo.amount;
        }
    }

    Ok((selected, change))
}

/// Select boarding outputs and VTXOs to be used as inputs in onchain transactions, exiting the Ark
/// ecosystem.
///
/// This function prioritizes boarding outputs over VTXOs. That is, we may not select any VTXOs if
/// the `target_amount` is covered using only boarding outputs.
///
/// TODO: We should use a coin selection algorithm that takes into account fees e.g.
/// https://github.com/bitcoindevkit/coin-select.
pub async fn coin_select_for_onchain<B, W>(
    client: &Client<B, W>,
    target_amount: Amount,
) -> Result<
    (
        Vec<(BoardingOutput, OutPoint, Amount)>,
        Vec<(DefaultVtxo, OutPoint, Amount)>,
        Amount,
    ),
    Error,
>
where
    B: Blockchain,
    W: BoardingWallet + OnchainWallet,
{
    let wallet = client.inner.wallet().await;
    let boarding_outputs = wallet.get_boarding_outputs()?;

    let now = std::time::UNIX_EPOCH
        .elapsed()
        .map_err(Error::coin_select)?;

    let mut selected_boarding_outputs = Vec::new();
    let mut selected_amount = Amount::ZERO;

    for boarding_output in boarding_outputs.iter() {
        if target_amount <= selected_amount {
            let change_amount = selected_amount - target_amount;
            return Ok((selected_boarding_outputs, Vec::new(), change_amount));
        }

        let outpoints = client
            .blockchain()
            .find_outpoints(boarding_output.address())
            .await?;

        for o in outpoints.iter() {
            // Find outpoints for each boarding output.
            if let ExplorerUtxo {
                outpoint,
                amount,
                confirmation_blocktime: Some(confirmation_blocktime),
            } = o
            {
                let spendable_at = Duration::from_secs(*confirmation_blocktime)
                    + boarding_output.exit_delay_duration();

                // For each confirmed outpoint, check if they can already be spent unilaterally
                // using the exit path.
                if spendable_at <= now {
                    tracing::debug!(?outpoint, %amount, ?boarding_output, "Selected boarding output");

                    selected_boarding_outputs.push((boarding_output.clone(), *outpoint, *amount));
                    selected_amount += *amount;
                }
            }
        }
    }

    let mut selected_vtxo_outputs = Vec::new();

    for (_, vtxo) in client.get_offchain_addresses() {
        if target_amount <= selected_amount {
            let change_amount = selected_amount - target_amount;

            return Ok((
                selected_boarding_outputs,
                selected_vtxo_outputs,
                change_amount,
            ));
        }

        let outpoints = client.blockchain().find_outpoints(vtxo.address()).await?;

        for o in outpoints.iter() {
            // Find outpoints for each VTXO.
            if let ExplorerUtxo {
                outpoint,
                amount,
                confirmation_blocktime: Some(confirmation_blocktime),
            } = o
            {
                let spendable_at =
                    Duration::from_secs(*confirmation_blocktime) + vtxo.exit_delay_duration();

                // For each confirmed outpoint, check if they can already be spent unilaterally
                // using the exit path.
                if spendable_at <= now {
                    tracing::debug!(?outpoint, %amount, ?vtxo, "Selected VTXO");

                    selected_vtxo_outputs.push((vtxo.clone(), *outpoint, *amount));
                    selected_amount += *amount;
                }
            }
        }
    }

    if selected_amount < target_amount {
        return Err(Error::coin_select(format!(
            "insufficient funds: selected = {selected_amount}, needed = {target_amount}"
        )));
    }

    let change_amount = selected_amount - target_amount;

    Ok((
        selected_boarding_outputs,
        selected_vtxo_outputs,
        change_amount,
    ))
}

// Tests for the coin selection function
#[cfg(test)]
mod tests {
    use super::*;

    fn vtxo(expire_at: i64, amount: Amount) -> VtxoOutPoint {
        VtxoOutPoint {
            outpoint: None,
            spent: false,
            round_txid: "".to_string(),
            spent_by: "".to_string(),
            expire_at,
            swept: false,
            redeem_tx: "".to_string(),
            amount,
            pubkey: "".to_string(),
            created_at: 0,
        }
    }

    #[test]
    fn test_basic_coin_selection() {
        let vtxos = vec![vtxo(123456789, Amount::from_sat(3000))];

        let result =
            coin_select_for_oor(vtxos, Amount::from_sat(2500), Amount::from_sat(100), true);
        assert!(result.is_ok());

        let (selected, change) = result.unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(change, Amount::from_sat(500));
    }

    #[test]
    fn test_insufficient_funds() {
        let vtxos = vec![vtxo(123456789, Amount::from_sat(100))];

        let result = coin_select_for_oor(vtxos, Amount::from_sat(1000), Amount::from_sat(50), true);
        assert!(result.is_err());
    }
}

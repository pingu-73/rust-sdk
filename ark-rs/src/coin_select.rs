use crate::asp::VtxoOutPoint;
use crate::error::Error;
use bitcoin::Amount;

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
            is_oor: false,
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

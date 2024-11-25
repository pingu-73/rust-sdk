use crate::asp::VtxoOutPoint;
use crate::error::Error;
use bitcoin::Amount;

#[derive(Clone)]
pub struct Utxo {
    pub amount: Amount,
}

pub fn coin_select(
    boarding_utxos: Vec<Utxo>,
    mut vtxo_outpoints: Vec<VtxoOutPoint>,
    amount: Amount,
    dust: Amount,
    sort_by_expiration_time: bool,
) -> Result<(Vec<Utxo>, Vec<VtxoOutPoint>, Amount), Error> {
    let mut selected = Vec::new();
    let mut not_selected = Vec::new();
    let mut selected_boarding = Vec::new();
    let mut not_selected_boarding = Vec::new();
    let mut selected_amount = Amount::ZERO;

    if sort_by_expiration_time {
        // Sort vtxos by expiration (older first)
        vtxo_outpoints.sort_by(|a, b| a.expire_at.cmp(&b.expire_at));

        // Sort boarding utxos by spendable time
        // boarding_utxos.sort_by(|a, b| a.spendable_at.cmp(&b.spendable_at));
        // TODO: the Go implementation is selecting oldest first, not sure we need this.
    }

    // Process boarding UTXOs
    for utxo in boarding_utxos {
        if selected_amount >= amount {
            not_selected_boarding.push(utxo);
        } else {
            selected_boarding.push(utxo.clone());
            selected_amount += utxo.amount;
        }
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
        return Err(Error::Unknown);
    }

    let mut change = selected_amount - amount;

    if change < dust {
        if let Some(vtxo) = not_selected.first() {
            selected.push(vtxo.clone());
            change += vtxo.amount;
        } else if let Some(utxo) = not_selected_boarding.first() {
            selected_boarding.push(utxo.clone());
            change += utxo.amount;
        }
    }

    Ok((selected_boarding, selected, change))
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
        let boarding_utxos = vec![Utxo {
            amount: Amount::from_sat(1000),
        }];

        let vtxos = vec![vtxo(123456789, Amount::from_sat(2000))];

        let result = coin_select(
            boarding_utxos,
            vtxos,
            Amount::from_sat(2500),
            Amount::from_sat(100),
            true,
        );
        assert!(result.is_ok());

        let (selected_boarding, selected, change) = result.unwrap();
        assert_eq!(selected_boarding.len(), 1);
        assert_eq!(selected.len(), 1);
        assert_eq!(change, Amount::from_sat(500));
    }

    #[test]
    fn test_insufficient_funds() {
        let boarding_utxos = vec![Utxo {
            amount: Amount::from_sat(100),
        }];

        let vtxos = vec![vtxo(123456789, Amount::from_sat(100))];

        let result = coin_select(
            boarding_utxos,
            vtxos,
            Amount::from_sat(1000),
            Amount::from_sat(50),
            true,
        );
        assert!(result.is_err());
    }
}

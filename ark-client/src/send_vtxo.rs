use crate::error::ErrorContext;
use crate::wallet::BoardingWallet;
use crate::wallet::OnchainWallet;
use crate::Blockchain;
use crate::Client;
use crate::Error;
use ark_core::coin_select::select_vtxos;
use ark_core::redeem;
use ark_core::redeem::create_and_sign_redeem_transaction;
use ark_core::ArkAddress;
use bitcoin::Amount;
use bitcoin::Psbt;

impl<B, W> Client<B, W>
where
    B: Blockchain,
    W: BoardingWallet + OnchainWallet,
{
    pub async fn send_vtxo(&self, address: ArkAddress, amount: Amount) -> Result<Psbt, Error> {
        let spendable_vtxos = self
            .spendable_vtxos()
            .await
            .context("failed to get spendable VTXOs")?;

        // Run coin selection algorithm on candidate spendable VTXOs.
        let spendable_vtxo_outpoints = spendable_vtxos
            .iter()
            .flat_map(|(vtxos, _)| vtxos.clone())
            .map(|vtxo| ark_core::coin_select::VtxoOutPoint {
                outpoint: vtxo.outpoint.expect("outpoint"),
                expire_at: vtxo.expire_at,
                amount: vtxo.amount,
            })
            .collect::<Vec<_>>();

        let selected_coins = select_vtxos(
            spendable_vtxo_outpoints,
            amount,
            self.server_info.dust,
            true,
        )
        .map_err(Error::from)
        .context("failed to select coins")?;

        let vtxo_inputs = selected_coins
            .into_iter()
            .map(|vtxo_outpoint| {
                let vtxo = spendable_vtxos
                    .clone()
                    .into_iter()
                    .find_map(|(vtxo_outpoints, vtxo)| {
                        vtxo_outpoints
                            .iter()
                            .any(|v| {
                                v.outpoint
                                    .map(|o| o == vtxo_outpoint.outpoint)
                                    .unwrap_or(false)
                            })
                            .then_some(vtxo)
                    })
                    .expect("to find matching default VTXO");

                redeem::VtxoInput::new(vtxo, vtxo_outpoint.amount, vtxo_outpoint.outpoint)
            })
            .collect::<Vec<_>>();

        let (change_address, _) = self.get_offchain_address();

        let signed_redeem_psbt = create_and_sign_redeem_transaction(
            self.kp(),
            &address,
            amount,
            &change_address,
            &vtxo_inputs,
        )
        .map_err(Error::from)?;

        self.network_client()
            .submit_redeem_transaction(signed_redeem_psbt.clone())
            .await
            .map_err(Error::ark_server)
            .context("failed to complete payment request")?;

        Ok(signed_redeem_psbt)
    }
}

use crate::ark_address::ArkAddress;
use crate::asp::types::Info;
use crate::asp::types::ListVtxo;
use crate::asp::types::Vtxo;
use crate::error::Error;
use crate::generated::ark::v1::ark_service_client::ArkServiceClient;
use crate::generated::ark::v1::{AsyncPaymentInput, Input, ListVtxosRequest, Outpoint, Output};
use crate::generated::ark::v1::{CreatePaymentRequest, GetInfoRequest};
use base64::Engine;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::{Amount, OutPoint, Psbt, TapLeafHash};
use tonic::transport::Channel;

pub struct PaymentInput {
    pub forfeit_leaf_hash: TapLeafHash,
    pub outpoint: Option<OutPoint>,
    pub descriptor: String,
}

pub struct PaymentOutput {
    pub address: ArkAddress,
    pub amount: Amount,
}

pub struct Client {
    url: String,
    // TODO: Make this not public and fix everything in the world. Can still expose, but via a
    // method.
    pub inner: Option<ArkServiceClient<Channel>>,
}

impl Client {
    pub fn new(url: String) -> Self {
        Self { url, inner: None }
    }

    pub async fn connect(&mut self) -> Result<(), Error> {
        let client = ArkServiceClient::connect(self.url.clone()).await.unwrap();

        self.inner = Some(client);
        Ok(())
    }

    pub async fn get_info(&self) -> Result<Info, Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let response = inner.get_info(GetInfoRequest {}).await.unwrap();

        response.into_inner().try_into()
    }

    pub async fn list_vtxos(&self, address: ArkAddress) -> Result<ListVtxo, Error> {
        let address = address.encode()?;

        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let response = inner
            .list_vtxos(ListVtxosRequest { address })
            .await
            .unwrap();
        let spent: Result<Vec<Vtxo>, Error> = response
            .get_ref()
            .spendable_vtxos
            .iter()
            .map(Vtxo::try_from)
            .collect();
        let spendable: Result<Vec<Vtxo>, Error> = response
            .get_ref()
            .spendable_vtxos
            .iter()
            .map(Vtxo::try_from)
            .collect();

        Ok(ListVtxo {
            spent: spent?,
            spendable: spendable?,
        })
    }

    pub async fn send_payment(
        &self,
        inputs: Vec<PaymentInput>,
        outputs: Vec<PaymentOutput>,
    ) -> Result<Psbt, Error> {
        let inputs = inputs
            .iter()
            .map(|input| {
                // The ASP reverses this for some reason.
                let mut leaf_hash = input.forfeit_leaf_hash.to_byte_array();
                leaf_hash.reverse();

                AsyncPaymentInput {
                    input: Some(Input {
                        outpoint: input.outpoint.map(|outpoint| Outpoint {
                            txid: outpoint.txid.to_string(),
                            vout: outpoint.vout,
                        }),
                        descriptor: input.descriptor.clone(),
                    }),
                    forfeit_leaf_hash: leaf_hash.to_lower_hex_string(),
                }
            })
            .collect();

        let outputs = outputs
            .iter()
            .map(|output| Output {
                address: output.address.encode().unwrap(),
                amount: output.amount.to_sat(),
            })
            .collect();
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;
        let res = inner
            .create_payment(CreatePaymentRequest { inputs, outputs })
            .await
            .unwrap();

        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let signed_redeem_psbt = {
            let psbt = base64.decode(&res.into_inner().signed_redeem_tx).unwrap();

            Psbt::deserialize(&psbt).unwrap()
        };
        Ok(signed_redeem_psbt)
    }
}

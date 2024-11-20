use crate::ark_address::ArkAddress;
use crate::asp::types::Info;
use crate::asp::types::ListVtxo;
use crate::asp::types::Vtxo;
use crate::error::Error;
use crate::generated::ark::v1::ark_service_client::ArkServiceClient;
use crate::generated::ark::v1::AsyncPaymentInput;
use crate::generated::ark::v1::CompletePaymentRequest;
use crate::generated::ark::v1::CreatePaymentRequest;
use crate::generated::ark::v1::GetInfoRequest;
use crate::generated::ark::v1::Input;
use crate::generated::ark::v1::ListVtxosRequest;
use crate::generated::ark::v1::Outpoint;
use crate::generated::ark::v1::Output;
use crate::generated::ark::v1::RegisterInputsForNextRoundRequest;
use base64::Engine;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::TapLeafHash;
use bitcoin::Txid;
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

pub struct RoundInputs {
    pub outpoint: Option<OutPoint>,
    pub descriptor: String,
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

    pub async fn register_inputs_for_next_round(
        &self,
        ephemeral_key: PublicKey,
        inputs: Vec<RoundInputs>,
    ) -> Result<String, Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let inputs = inputs
            .iter()
            .map(|input| Input {
                outpoint: input.outpoint.map(|out| Outpoint {
                    txid: out.txid.to_string(),
                    vout: out.vout,
                }),
                descriptor: input.descriptor.clone(),
            })
            .collect();

        let response = inner
            .register_inputs_for_next_round(RegisterInputsForNextRoundRequest {
                inputs,
                ephemeral_pubkey: Some(ephemeral_key.to_string()),
            })
            .await
            .unwrap();
        let response = response.into_inner();

        Ok(response.id)
    }

    pub async fn send_payment(
        &self,
        inputs: Vec<PaymentInput>,
        outputs: Vec<PaymentOutput>,
    ) -> Result<Psbt, Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

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

    pub async fn complete_payment_request(&self, signed_psbt: Psbt) -> Result<Txid, Error> {
        let mut inner = self.inner.clone().ok_or(Error::AspNotConnected)?;

        let base64 = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );

        let signed_psbt_base64 = base64.encode(signed_psbt.serialize());

        let _response = inner
            .complete_payment(CompletePaymentRequest {
                signed_redeem_tx: signed_psbt_base64,
            })
            .await
            .unwrap();
        let txid = signed_psbt.unsigned_tx.compute_txid();

        Ok(txid)
    }
}

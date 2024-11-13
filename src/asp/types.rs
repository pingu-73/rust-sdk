use crate::generated;
use crate::BOARDING_DESCRIPTOR_TEMPLATE_MINISCRIPT;
use bitcoin::Amount;
use bitcoin::Network;
use bitcoin::OutPoint;
use bitcoin::Txid;
use miniscript::Descriptor;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct Info {
    pub pubkey: String,
    pub round_lifetime: i64,
    pub unilateral_exit_delay: i64,
    pub round_interval: i64,
    pub network: Network,
    pub dust: Amount,
    pub boarding_descriptor_template: Descriptor<String>,
    pub vtxo_descriptor_templates: Vec<String>,
    pub forfeit_address: String,
    pub orig_boarding_descriptor: String,
}

impl TryFrom<generated::ark::v1::GetInfoResponse> for Info {
    type Error = crate::Error;

    fn try_from(value: generated::ark::v1::GetInfoResponse) -> Result<Self, Self::Error> {
        // TODO: Use descriptor from ASP when the ASP supports Miniscript.
        // let boarding_descriptor = asp_info.boarding_descriptor_template.replace(' ', "");

        let boarding_descriptor = BOARDING_DESCRIPTOR_TEMPLATE_MINISCRIPT
            .replace("TIMEOUT", value.round_lifetime.to_string().as_str());
        let boarding_descriptor = Descriptor::<String>::from_str(&boarding_descriptor).unwrap();
        let orig_boarding_descriptor = value.boarding_descriptor_template;

        debug_assert!(boarding_descriptor.sanity_check().is_ok());

        Ok(Info {
            pubkey: value.pubkey,
            round_lifetime: value.round_lifetime,
            unilateral_exit_delay: value.unilateral_exit_delay,
            round_interval: value.round_interval,
            network: Network::from_str(value.network.as_str())
                .map_err(|_| crate::Error::InvalidResponseType)?,
            dust: Amount::from_sat(value.dust as u64),
            boarding_descriptor_template: boarding_descriptor,
            vtxo_descriptor_templates: value.vtxo_descriptor_templates,
            forfeit_address: value.forfeit_address,
            orig_boarding_descriptor,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Vtxo {
    pub outpoint: Option<OutPoint>,
    pub spent: bool,
    pub round_txid: String,
    pub spent_by: String,
    pub expire_at: i64,
    pub swept: bool,
    pub is_oor: bool,
    pub redeem_tx: String,
    pub amount: Amount,
    pub pubkey: String,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct ListVtxo {
    pub spent: Vec<Vtxo>,
    pub spendable: Vec<Vtxo>,
}

impl TryFrom<&generated::ark::v1::Vtxo> for Vtxo {
    type Error = crate::Error;

    fn try_from(value: &generated::ark::v1::Vtxo) -> Result<Self, Self::Error> {
        Ok(Vtxo {
            outpoint: value.outpoint.clone().map(|out| OutPoint {
                txid: Txid::from_str(out.txid.as_str()).unwrap(),
                vout: out.vout,
            }),
            spent: value.spent,
            round_txid: value.round_txid.clone(),
            spent_by: value.spent_by.clone(),
            expire_at: value.expire_at,
            swept: value.swept,
            is_oor: value.is_oor,
            redeem_tx: value.redeem_tx.clone(),
            amount: Amount::from_sat(value.amount),
            pubkey: value.pubkey.clone(),
            created_at: value.created_at,
        })
    }
}

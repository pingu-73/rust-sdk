use bech32::Bech32m;
use bech32::Hrp;
use bitcoin::key::TweakedPublicKey;
use bitcoin::Network;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;

#[derive(Debug, Clone, Copy)]
pub struct ArkAddress {
    hrp: Hrp,
    asp: XOnlyPublicKey,
    vtxo_tap_key: TweakedPublicKey,
}

impl ArkAddress {
    pub fn to_p2tr_script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.vtxo_tap_key)
    }
}

impl ArkAddress {
    pub fn new(network: Network, asp: XOnlyPublicKey, vtxo_tap_key: TweakedPublicKey) -> Self {
        let hrp = match network {
            Network::Bitcoin => "ark",
            _ => "tark",
        };

        let hrp = Hrp::parse_unchecked(hrp);

        Self {
            hrp,
            asp,
            vtxo_tap_key,
        }
    }

    pub fn encode(&self) -> String {
        let mut bytes = [0u8; 64];

        bytes[..32].copy_from_slice(&self.asp.serialize());
        bytes[32..].copy_from_slice(&self.vtxo_tap_key.serialize());

        bech32::encode::<Bech32m>(self.hrp, bytes.as_slice()).expect("data can be encoded")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hex::DisplayHex;

    impl ArkAddress {
        fn decode(value: &str) -> Self {
            let (hrp, bytes) = bech32::decode(value).unwrap();

            let asp = XOnlyPublicKey::from_slice(&bytes[..32]).unwrap();
            let vtxo_tap_key = XOnlyPublicKey::from_slice(&bytes[32..]).unwrap();

            // This is only okay because we are using this for testing.
            let vtxo_tap_key = TweakedPublicKey::dangerous_assume_tweaked(vtxo_tap_key);

            Self {
                hrp,
                asp,
                vtxo_tap_key,
            }
        }
    }

    // Taken from https://github.com/ark-network/ark/blob/b536a9e65252573aaa48110ef5d0c90894eb550c/common/fixtures/encoding.json.
    #[tokio::test]
    pub async fn roundtrip() {
        let address = "tark1x0lm8hhr2wc6n6lyemtyh9rz8rg2ftpkfun46aca56kjg3ws0tsztfpuanaquxc6faedvjk3tax0575y6perapg3e95654pk8r4fjecs5fyd2";

        let decoded = ArkAddress::decode(address);

        let hrp = decoded.hrp.to_string();
        assert_eq!(hrp, "tark");

        let asp = decoded.asp.serialize().as_hex().to_string();
        assert_eq!(
            asp,
            "33ffb3dee353b1a9ebe4ced64b946238d0a4ac364f275d771da6ad2445d07ae0"
        );

        let vtxo_tap_key = decoded.vtxo_tap_key.serialize().as_hex().to_string();
        assert_eq!(
            vtxo_tap_key,
            "25a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967"
        );

        let encoded = decoded.encode();

        assert_eq!(encoded, address);
    }
}

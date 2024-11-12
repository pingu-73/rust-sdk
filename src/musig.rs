use bitcoin::key::Keypair;
use bitcoin::secp256k1::PublicKey;
use bitcoin::XOnlyPublicKey;

pub fn to_zkp_pk(pk: PublicKey) -> zkp::PublicKey {
    zkp::PublicKey::from_slice(&pk.serialize()).unwrap()
}

pub fn from_zkp_xonly(pk: zkp::XOnlyPublicKey) -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&pk.serialize()).unwrap()
}

pub fn to_zkp_kp<C>(secp: &zkp::Secp256k1<C>, kp: &Keypair) -> zkp::Keypair
where
    C: zkp::Signing,
{
    zkp::Keypair::from_seckey_slice(secp, &kp.secret_bytes()).unwrap()
}

#[cfg(test)]
mod tests {
    #![allow(dead_code)]

    use super::*;
    use crate::script::CsvSigClosure;
    use bitcoin::hex::DisplayHex;
    use bitcoin::hex::FromHex;
    use bitcoin::key::Keypair;
    use bitcoin::key::PublicKey;
    use bitcoin::key::Secp256k1;
    use bitcoin::key::UntweakedPublicKey;
    use bitcoin::taproot::TaprootBuilder;
    use bitcoin::Amount;
    use bitcoin::ScriptBuf;
    use std::str::FromStr;
    use zkp::new_musig_nonce_pair;
    use zkp::MusigKeyAggCache;
    use zkp::MusigSessionId;

    struct Receiver {
        amount: Amount,
        pk: PublicKey,
    }

    #[test]
    fn musig_protocol() {
        let lifetime = 1024;

        // TODO: Test with more receiver combinations.
        let receivers = [Receiver {
            pk: PublicKey::from_str(
                "020000000000000000000000000000000000000000000000000000000000000002",
            )
            .unwrap(),
            amount: Amount::from_sat(1100),
        }];

        let secp = Secp256k1::new();

        let alice_kp = Keypair::from_seckey_str(
            &secp,
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let bob_kp = Keypair::from_seckey_str(
            &secp,
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let asp_kp = Keypair::from_seckey_str(
            &secp,
            "0000000000000000000000000000000000000000000000000000000000000003",
        )
        .unwrap();

        let _cosigners = [
            alice_kp.public_key(),
            bob_kp.public_key(),
            asp_kp.public_key(),
        ];

        let _shared_output_amount = receivers.iter().fold(Amount::ZERO, |acc, r| r.amount + acc);

        // Took this from the go test.
        let psbt = Vec::from_hex("70736274FF01005E020000000112CD1BE25D19566EC3FB9EDD2BE2CBB9EEB781E7ADF80219E99B89CC4A66F8490000000000FFFFFFFF014C04000000000000225120000000000000000000000000000000000000000000000000000000000000000200000000002215C16412FB50411F0FFBF400F5F12372FC67C97B21A6871C187A6E618D171A9B88742903020040B2692055632E6B071D56922509ECBB920FBE72FAD6AE2F2B2D7EEFC2CDC74E2D71A282ACC00117206412FB50411F0FFBF400F5F12372FC67C97B21A6871C187A6E618D171A9B887409636F7369676E657200210255632E6B071D56922509ECBB920FBE72FAD6AE2F2B2D7EEFC2CDC74E2D71A28209636F7369676E65720121033C4B4ADD44261D56A407C86D2CA057FD535A0BBC73D404FD02C6B2033468997809636F7369676E6572022103B7F1FAA5880547046CF7B9EFC6455C169F1E38181C8B97456CF81D461D11E2580000").unwrap();
        let psbt = bitcoin::psbt::Psbt::deserialize(&psbt).unwrap();
        let _congestion_tree = [[psbt]];

        let sweep_closure = CsvSigClosure {
            pk: asp_kp.public_key(),
            timeout: lifetime,
        };

        let sweep_tap_leaf = sweep_closure.leaf();

        let sweep_tap_tree = {
            let (script, version) = sweep_tap_leaf.as_script().unwrap();

            TaprootBuilder::new()
                .add_leaf_with_ver(0, ScriptBuf::from(script), version)
                .unwrap()
                .finalize(
                    &secp,
                    UntweakedPublicKey::from_str(
                        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
                    )
                    .unwrap(),
                )
        }
        .unwrap();

        // It's flipped in the go implementation! We may need to reverse it when we send it over the
        // wire.
        assert_eq!(
            sweep_tap_tree.merkle_root().unwrap().to_string(),
            "ac38b55b108a0f3493763668e58a08d8e25f52cbd2b4bd7175a8252f8f9f6e77"
        );

        let secp_zkp = zkp::Secp256k1::new();

        let _key_agg_cache = MusigKeyAggCache::new(
            &secp_zkp,
            &[
                to_zkp_pk(alice_kp.public_key()),
                to_zkp_pk(bob_kp.public_key()),
                to_zkp_pk(asp_kp.public_key()),
            ],
        );

        // TODO: Make sure that we call it like the Ark does.
        let alice_session_id = MusigSessionId::assume_unique_per_nonce_gen([1u8; 32]);
        let (_alice_nonce_sk, alice_nonce_pk) = new_musig_nonce_pair(
            &secp_zkp,
            alice_session_id,
            None,
            // Some(to_zkp_kp(&secp_zkp, &alice_kp).secret_key()),
            None,
            to_zkp_pk(alice_kp.public_key()),
            None,
            None,
        )
        .unwrap();

        let bob_session_id = MusigSessionId::assume_unique_per_nonce_gen([2u8; 32]);
        let (_bob_nonce_sk, bob_nonce_pk) = new_musig_nonce_pair(
            &secp_zkp,
            bob_session_id,
            None,
            None,
            to_zkp_pk(alice_kp.public_key()),
            None,
            None,
        )
        .unwrap();

        let asp_session_id = MusigSessionId::assume_unique_per_nonce_gen([3u8; 32]);
        let (_asp_nonce_sk, asp_nonce_pk) = new_musig_nonce_pair(
            &secp_zkp,
            asp_session_id,
            None,
            None,
            to_zkp_pk(alice_kp.public_key()),
            None,
            None,
        )
        .unwrap();

        dbg!(asp_nonce_pk.serialize().to_lower_hex_string());
        dbg!(alice_nonce_pk.serialize().to_lower_hex_string());
        dbg!(bob_nonce_pk.serialize().to_lower_hex_string());

        // zkp::musig::MusigSession::new(secp, key_agg_cache, agg_nonce, msg).partial_sign(
        //     secp,
        //     secnonce,
        //     keypair,
        //     key_agg_cache,
        // )

        // let session = MusigSession::new(&secp, key_agg_cache, agg_nonce, msg);

        // session.nonce_parity()
    }
}

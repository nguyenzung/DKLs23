use wasm_bindgen::prelude::*;
use dkls23_core::protocols::{Parameters, PartyIndex};
use dkls23_core::protocols::re_key::re_key;
use k256;
use elliptic_curve::ops::Reduce;

#[wasm_bindgen]
pub fn run_dkg_dsg_t3_n5() -> JsValue {
    // Fixed parameters: threshold=3, n=5
    let parameters = Parameters { threshold: 3, share_count: 5 };

    // Deterministic session_id and secret_key for WASM demo (fixed test vectors)
    let session_id = [0u8; 32];
    // use fixed scalar via hex (64 hex chars = 32 bytes)
    let secret_u256 = k256::U256::from_be_hex("0101010101010101010101010101010101010101010101010101010101010101");
    let secret_key = k256::Scalar::reduce(&secret_u256);

    // Run re_key (which includes DKG-like initialization) to get parties
    let (parties, _info) = re_key::<k256::Secp256k1>(&parameters, &session_id, &secret_key, None, |_| String::new());

    // Prepare sign data for first 3 parties (1..=3)
    let sign_id = [2u8; 32];
    let message_hash = dkls23_core::utilities::hashes::tagged_hash(b"wasm-demo", &[b"Hello WASM"]);

    let executing_parties: Vec<u8> = vec![1,2,3];
    let mut all_data = std::collections::BTreeMap::new();
    for &party_index in &executing_parties {
        let counterparties: Vec<PartyIndex> = executing_parties.iter().filter(|&&i| i != party_index).map(|&i| PartyIndex::new(i).unwrap()).collect();
        all_data.insert(party_index, dkls23_core::protocols::signing::SignData { sign_id: sign_id.to_vec(), counterparties, message_hash });
    }

    // Build sessions
    let mut sessions = std::collections::BTreeMap::new();
    let mut transmit_1to2 = std::collections::BTreeMap::new();
    for &party_index in &executing_parties {
        let (session, transmit) = dkls23_core::protocols::sign_session::SignSession::new(&parties[(party_index-1) as usize], all_data.get(&party_index).unwrap().clone()).unwrap();
        sessions.insert(party_index, session);
        transmit_1to2.insert(party_index, transmit);
    }

    // Route messages round 1
    let mut received_1to2 = std::collections::BTreeMap::new();
    for &party_index in &executing_parties {
        let pi = PartyIndex::new(party_index).unwrap();
        let msgs: Vec<_> = transmit_1to2.values().flatten().filter(|m| m.parties.receiver == pi).cloned().collect();
        received_1to2.insert(party_index, msgs);
    }

    // Phase 2
    let mut transmit_2to3 = std::collections::BTreeMap::new();
    for &party_index in &executing_parties {
        let transmit = sessions.get_mut(&party_index).unwrap().phase2(received_1to2.get(&party_index).unwrap()).unwrap();
        transmit_2to3.insert(party_index, transmit);
    }

    // Route messages round 2
    let mut received_2to3 = std::collections::BTreeMap::new();
    for &party_index in &executing_parties {
        let pi = PartyIndex::new(party_index).unwrap();
        let msgs: Vec<_> = transmit_2to3.values().flatten().filter(|m| m.parties.receiver == pi).cloned().collect();
        received_2to3.insert(party_index, msgs);
    }

    // Phase 3
    let mut broadcasts = Vec::new();
    for &party_index in &executing_parties {
        let broadcast = sessions.get_mut(&party_index).unwrap().phase3(received_2to3.get(&party_index).unwrap()).unwrap();
        broadcasts.push(broadcast);
    }

    // Phase 4
    let some_index = executing_parties[0];
    let session = sessions.remove(&some_index).unwrap();
    let signature = session.phase4(&broadcasts, true).unwrap();

    // Return signature as JSON string
    let mut obj = serde_json::Map::new();
    obj.insert("r".to_string(), serde_json::Value::String(hex::encode(signature.r)));
    obj.insert("s".to_string(), serde_json::Value::String(hex::encode(signature.s)));
    obj.insert("recov".to_string(), serde_json::Value::Number(serde_json::Number::from(signature.recovery_id as u8)));

    JsValue::from_str(&serde_json::Value::Object(obj).to_string())
}

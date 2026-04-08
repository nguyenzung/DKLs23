// End-to-end examples that simulate party communication using PhaseOutput/PhaseInput
// Four tests: DKG, Distributed Signing (DSG), Refresh, Resharing
// These tests build on the crate's public API and exercise frame encoding/decoding
// via `protocols::messages::{PhaseOutput, PhaseInput}` so they simulate how
// messages would be broadcast / sent P2P in the real network.

use std::collections::BTreeMap;

use dkls23_core::protocols::messages::{PhaseInput, PhaseOutput};
use dkls23_core::protocols::re_key::re_key;
use dkls23_core::protocols::{Parameters, PartyIndex};
use dkls23_core::DkgSession;

use dkls23_core::protocols::dkg::BroadcastDerivationPhase2to4;
use dkls23_core::protocols::dkg::BroadcastDerivationPhase3to4;
use dkls23_core::protocols::dkg::ProofCommitment;
use dkls23_core::protocols::dkg::TransmitInitMulPhase3to4;
use dkls23_core::protocols::dkg::TransmitInitZeroSharePhase2to4;
use dkls23_core::protocols::dkg::TransmitInitZeroSharePhase3to4;
use dkls23_core::protocols::signing::verify_ecdsa_signature;
use dkls23_core::protocols::signing::Broadcast3to4;
use dkls23_core::protocols::signing::SignData;
use dkls23_core::protocols::signing::TransmitPhase1to2;
use dkls23_core::protocols::signing::TransmitPhase2to3;
use k256::elliptic_curve::ops::Reduce;
use k256::Secp256k1;

use dkls23_core::utilities::rng;
use rand::RngExt;

const SESSION_ID_LEN: usize = 32;

// ── Resharing helpers ─────────────────────────────────────────────────────────

/// Run all 4 DkgSession phases and return the resulting [`Party`] vector.
///
/// Handles all message routing internally (transpose, p2p filter).
fn run_reshare_sessions(
    mut sessions: Vec<DkgSession<Secp256k1>>,
) -> Vec<dkls23_core::protocols::Party<Secp256k1>> {
    let n = sessions.len();

    // Phase 1: polynomial fragments.
    let mut frags: Vec<Vec<k256::Scalar>> = Vec::with_capacity(n);
    for s in sessions.iter_mut() {
        frags.push(s.phase1().unwrap());
    }
    // Transpose: poly_frags[j] = fragments destined for party j.
    let mut poly_frags = vec![Vec::<k256::Scalar>::with_capacity(n); n];
    for row in frags {
        for j in 0..n {
            poly_frags[j].push(row[j]);
        }
    }

    // Phase 2.
    let mut proofs: Vec<ProofCommitment<Secp256k1>> = Vec::with_capacity(n);
    let mut zt2: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    let mut bip2: BTreeMap<PartyIndex, BroadcastDerivationPhase2to4> = BTreeMap::new();
    let mut party_indices: Vec<PartyIndex> = Vec::with_capacity(n);

    for (i, s) in sessions.iter_mut().enumerate() {
        let (pc, zt, bb) = s.phase2(&poly_frags[i]).unwrap();
        party_indices.push(bb.sender_index);
        proofs.push(pc);
        zt2.push(zt);
        bip2.insert(bb.sender_index, bb);
    }

    // Route phase-2 p2p.
    let mut zr2: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    for pi in &party_indices {
        zr2.push(
            zt2.iter()
                .flat_map(|v| v.iter())
                .filter(|m| &m.parties.receiver == pi)
                .cloned()
                .collect(),
        );
    }

    // Phase 3.
    let mut zt3: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mt3: Vec<Vec<TransmitInitMulPhase3to4<Secp256k1>>> = Vec::with_capacity(n);
    let mut bip3: BTreeMap<PartyIndex, BroadcastDerivationPhase3to4> = BTreeMap::new();

    for (_, s) in sessions.iter_mut().enumerate() {
        let (zt, mt, bb) = s.phase3().unwrap();
        zt3.push(zt);
        mt3.push(mt);
        bip3.insert(bb.sender_index, bb);
    }

    // Route phase-3 p2p.
    let mut zr3: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mr3: Vec<Vec<TransmitInitMulPhase3to4<Secp256k1>>> = Vec::with_capacity(n);
    for pi in &party_indices {
        zr3.push(
            zt3.iter()
                .flat_map(|v| v.iter())
                .filter(|m| &m.parties.receiver == pi)
                .cloned()
                .collect(),
        );
        mr3.push(
            mt3.iter()
                .flat_map(|v| v.iter())
                .filter(|m| &m.parties.receiver == pi)
                .cloned()
                .collect(),
        );
    }

    // Phase 4.
    sessions
        .into_iter()
        .enumerate()
        .map(|(i, s)| {
            let (party, _) = s
                .phase4(&proofs, &zr2[i], &zr3[i], &mr3[i], &bip2, &bip3, |_| {
                    String::new()
                })
                .unwrap_or_else(|abort| panic!("Party phase4 aborted: {:?}", abort.description()));
            party
        })
        .collect()
}

/// Sign `message_hash` using the given `executing` party-index subset and verify the result.
///
/// Panics if any phase fails or if the final ECDSA signature does not verify.
fn sign_and_verify_reshare(
    parties: &[dkls23_core::protocols::Party<Secp256k1>],
    executing: &[u8],
    message_hash: dkls23_core::utilities::hashes::HashOutput,
) {
    use dkls23_core::SignSession;

    let sign_id = rng::get_rng().random::<[u8; 32]>();

    // Phase 1 — create sessions.
    let mut sessions: BTreeMap<u8, SignSession<'_, Secp256k1>> = BTreeMap::new();
    let mut tx1: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();

    for &i in executing {
        let counterparties: Vec<PartyIndex> = executing
            .iter()
            .filter(|&&j| j != i)
            .map(|&j| PartyIndex::new(j).unwrap())
            .collect();
        let data = SignData {
            sign_id: sign_id.to_vec(),
            counterparties,
            message_hash,
        };
        let party = parties
            .iter()
            .find(|p| p.party_index.as_u8() == i)
            .unwrap_or_else(|| panic!("Party {} not found in slice", i));
        let (sess, transmit) = SignSession::new(party, data).unwrap_or_else(|abort| {
            panic!(
                "SignSession::new failed for party {}: {:?}",
                i,
                abort.description()
            )
        });
        sessions.insert(i, sess);
        tx1.insert(i, transmit);
    }

    // Route phase-1 messages.
    let mut rx1: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
    for &i in executing {
        let pi = PartyIndex::new(i).unwrap();
        rx1.insert(
            i,
            tx1.values()
                .flatten()
                .filter(|m| m.parties.receiver == pi)
                .cloned()
                .collect(),
        );
    }

    // Phase 2.
    let mut tx2: BTreeMap<u8, Vec<TransmitPhase2to3<Secp256k1>>> = BTreeMap::new();
    for &i in executing {
        let transmit = sessions
            .get_mut(&i)
            .unwrap()
            .phase2(rx1.get(&i).unwrap())
            .unwrap_or_else(|abort| {
                panic!("Phase2 aborted for party {}: {:?}", i, abort.description())
            });
        tx2.insert(i, transmit);
    }

    // Route phase-2 messages.
    let mut rx2: BTreeMap<u8, Vec<TransmitPhase2to3<Secp256k1>>> = BTreeMap::new();
    for &i in executing {
        let pi = PartyIndex::new(i).unwrap();
        rx2.insert(
            i,
            tx2.values()
                .flatten()
                .filter(|m| m.parties.receiver == pi)
                .cloned()
                .collect(),
        );
    }

    // Phase 3.
    let mut broadcasts: Vec<Broadcast3to4<Secp256k1>> = Vec::with_capacity(executing.len());
    for &i in executing {
        let bc = sessions
            .get_mut(&i)
            .unwrap()
            .phase3(rx2.get(&i).unwrap())
            .unwrap_or_else(|abort| {
                panic!("Phase3 aborted for party {}: {:?}", i, abort.description())
            });
        broadcasts.push(bc);
    }

    // Phase 4.
    let first = executing[0];
    let session = sessions.remove(&first).unwrap();
    let sig = session.phase4(&broadcasts, true).unwrap_or_else(|abort| {
        panic!(
            "Phase4 aborted for party {}: {:?}",
            first,
            abort.description()
        )
    });

    // Verify.
    assert_ne!(sig.r, [0u8; 32], "signature r should be non-zero");
    assert_ne!(sig.s, [0u8; 32], "signature s should be non-zero");

    let pk = parties
        .iter()
        .find(|p| p.party_index.as_u8() == first)
        .unwrap()
        .pk;
    let r_hex = hex::encode(sig.r);
    let s_hex = hex::encode(sig.s);
    assert!(
        verify_ecdsa_signature::<Secp256k1>(&message_hash, &pk, &r_hex, &s_hex),
        "ECDSA signature verification failed for executing parties {:?}",
        executing
    );
}

fn assemble_input_for_receiver(outputs: &BTreeMap<u8, PhaseOutput>, receiver: u8) -> PhaseInput {
    let mut broadcasts: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    let mut p2p: BTreeMap<u8, Vec<u8>> = BTreeMap::new();

    for (&sender, out) in outputs.iter() {
        if !out.broadcasts.is_empty() {
            let mut concat = Vec::new();
            for frame in &out.broadcasts {
                concat.extend_from_slice(frame);
            }
            broadcasts.insert(sender, concat);
        }
        if let Some(stream) = out.p2p.get(&receiver) {
            p2p.insert(sender, stream.clone());
        }
    }

    PhaseInput { broadcasts, p2p }
}

#[test]
fn e2e_dkg_using_phaseio() {
    // This test follows the DkgSession flow but uses PhaseOutput/PhaseInput
    // to simulate broadcast / p2p routing for the message structs (proofs,
    // zero-share init, mul init, derivation broadcasts).

    let threshold = rng::get_rng().random_range(2..=4);
    let offset = rng::get_rng().random_range(0..=2);
    let parameters = Parameters {
        threshold,
        share_count: threshold + offset,
    };
    let session_id = rng::get_rng().random::<[u8; SESSION_ID_LEN]>();

    let n = parameters.share_count as usize;

    // Create sessions
    let mut sessions: Vec<DkgSession<Secp256k1>> = (0..n)
        .map(|i| {
            DkgSession::new(
                parameters.clone(),
                PartyIndex::new(i as u8 + 1).unwrap(),
                session_id.to_vec(),
            )
        })
        .collect();

    // Phase1: polynomials (raw scalars) — handled directly (not framed)
    let mut dkg_1: Vec<Vec<k256::Scalar>> = Vec::with_capacity(n);
    for s in sessions.iter_mut() {
        dkg_1.push(s.phase1().unwrap());
    }

    // transpose
    let mut poly_fragments = vec![Vec::<k256::Scalar>::with_capacity(n); n];
    for row in dkg_1 {
        for j in 0..parameters.share_count as usize {
            poly_fragments[j].push(row[j]);
        }
    }

    // Phase2: each session produces a ProofCommitment (broadcast) and zero_transmit (p2p)
    let mut proof_commitments: Vec<ProofCommitment<Secp256k1>> = Vec::with_capacity(n);
    let mut per_sender_outputs: BTreeMap<u8, PhaseOutput> = BTreeMap::new();
    // Keep original per-sender transmit vectors so we can route by receiver deterministically
    let mut zero_tx_per_sender: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    let mut bip_phase2_map: BTreeMap<PartyIndex, BroadcastDerivationPhase2to4> = BTreeMap::new();

    for (i, sess) in sessions.iter_mut().enumerate() {
        let sender_id = (i as u8) + 1;
        let (proof_commitment, zero_transmit, bip_broadcast) =
            sess.phase2(&poly_fragments[i]).unwrap();
        proof_commitments.push(proof_commitment.clone());

        // frame the broadcast and p2p into a per-sender PhaseOutput
        let mut out = PhaseOutput::new();
        out.add_broadcast(&proof_commitment).unwrap();
        for msg in &zero_transmit {
            out.add_p2p(msg.parties.receiver.as_u8(), msg).unwrap();
        }
        per_sender_outputs.insert(sender_id, out);

        // store original vector for deterministic routing (kept for reference only)
        zero_tx_per_sender.push(zero_transmit);

        bip_phase2_map.insert(PartyIndex::new(sender_id).unwrap(), bip_broadcast);
    }

    // Communication round 2: assemble PhaseInput per receiver and decode proofs + p2p
    let mut zero_received_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    for recv_idx in 1..=parameters.share_count {
        let pi = recv_idx as u8;
        let input = assemble_input_for_receiver(&per_sender_outputs, pi);

        // Collect proofs broadcasted by every sender via the phased input (exercise framing)
        for sender in 1..=parameters.share_count {
            let _proof: ProofCommitment<Secp256k1> = input.get_broadcast(sender).unwrap();
        }

        // Collect p2p zero messages intended for this receiver by decoding from PhaseInput
        let mut row: Vec<TransmitInitZeroSharePhase2to4> = Vec::new();
        for sender in 1..=parameters.share_count {
            if sender == pi {
                continue;
            } // parties don't send p2p to themselves
              // decode via get_p2p — panic if missing to ensure test catches framing errors
            if let Ok(msg) = input.get_p2p::<TransmitInitZeroSharePhase2to4>(sender) {
                row.push(msg);
            } else {
                panic!(
                    "Missing zero-transmit from sender {} for receiver {}",
                    sender, pi
                );
            }
        }
        zero_received_2to4.push(row);
    }

    // Phase3: each session produces zero_transmit_3to4, mul_transmit_3to4 and bip broadcast
    let mut per_sender_outputs_round3: BTreeMap<u8, PhaseOutput> = BTreeMap::new();
    let mut zero_tx_3_all: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mul_tx_3_all: Vec<Vec<TransmitInitMulPhase3to4<Secp256k1>>> = Vec::with_capacity(n);
    let mut zero_tx3_per_sender: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mul_tx3_per_sender: Vec<Vec<TransmitInitMulPhase3to4<Secp256k1>>> =
        Vec::with_capacity(n);
    let mut bip_phase3_map: BTreeMap<PartyIndex, BroadcastDerivationPhase3to4> = BTreeMap::new();

    for (i, sess) in sessions.iter_mut().enumerate() {
        let sender_id = (i as u8) + 1;
        let (zero_transmit_3to4, mul_transmit_3to4, bip_broadcast) = sess.phase3().unwrap();

        // frame broadcasts and p2p for round 3 into per-sender PhaseOutput
        let mut out = PhaseOutput::new();
        out.add_broadcast(&bip_broadcast).unwrap();
        for msg in &zero_transmit_3to4 {
            out.add_p2p(msg.parties.receiver.as_u8(), msg).unwrap();
        }
        for msg in &mul_transmit_3to4 {
            out.add_p2p(msg.parties.receiver.as_u8(), msg).unwrap();
        }
        per_sender_outputs_round3.insert(sender_id, out);

        zero_tx_3_all.push(zero_transmit_3to4.clone());
        mul_tx_3_all.push(mul_transmit_3to4.clone());
        zero_tx3_per_sender.push(zero_transmit_3to4);
        mul_tx3_per_sender.push(mul_transmit_3to4);
        bip_phase3_map.insert(PartyIndex::new(sender_id).unwrap(), bip_broadcast);
    }

    // Communication round 3: assemble PhaseInput per receiver and decode p2p and bip broadcasts
    let mut zero_received_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4<Secp256k1>>> =
        Vec::with_capacity(n);

    for recv_idx in 1..=parameters.share_count {
        let pi = recv_idx as u8;
        let input = assemble_input_for_receiver(&per_sender_outputs_round3, pi);

        // Collect p2p zero and mul messages intended for this receiver by decoding from PhaseInput
        let mut zero_row: Vec<TransmitInitZeroSharePhase3to4> = Vec::new();
        let mut mul_row: Vec<TransmitInitMulPhase3to4<Secp256k1>> = Vec::new();
        for sender in 1..=parameters.share_count {
            if sender == pi {
                continue;
            }
            if let Ok(z) = input.get_p2p::<TransmitInitZeroSharePhase3to4>(sender) {
                zero_row.push(z);
            }
            if let Ok(m) = input.get_p2p::<TransmitInitMulPhase3to4<Secp256k1>>(sender) {
                mul_row.push(m);
            }
        }
        zero_received_3to4.push(zero_row);
        mul_received_3to4.push(mul_row);
    }

    // Phase 4
    let mut parties: Vec<dkls23_core::protocols::Party<Secp256k1>> = Vec::with_capacity(n);
    for (i, sess) in sessions.into_iter().enumerate() {
        let (party, _pkg) = sess
            .phase4(
                &proof_commitments,
                &zero_received_2to4[i],
                &zero_received_3to4[i],
                &mul_received_3to4[i],
                &bip_phase2_map,
                &bip_phase3_map,
                |_| String::new(),
            )
            .unwrap();
        parties.push(party);
    }

    let expected_pk = parties[0].pk;
    let expected_chain_code = parties[0].derivation_data.chain_code;
    for p in &parties {
        assert_eq!(expected_pk, p.pk);
        assert_eq!(expected_chain_code, p.derivation_data.chain_code);
    }
}

#[test]
fn e2e_signing_using_phaseio() {
    // Setup via re_key (trusted dealer) to obtain parties vector
    let threshold = rng::get_rng().random_range(2..=4);
    let offset = rng::get_rng().random_range(0..=2);
    let parameters = Parameters {
        threshold,
        share_count: threshold + offset,
    };
    let session_id = rng::get_rng().random::<[u8; SESSION_ID_LEN]>();

    // Use a fixed secret scalar (compatible with k256) to avoid RNG trait issues in tests
    let secret_key = k256::Scalar::reduce(&k256::U256::from_be_hex(
        "0249815B0D7E186DB61E7A6AAD6226608BB1C48B309EA8903CAB7A7283DA64A5",
    ));
    let (parties, _pkg) = re_key::<Secp256k1>(&parameters, &session_id, &secret_key, None, |_| {
        String::new()
    });

    // Choose executing parties 1..=threshold
    let executing: Vec<u8> = (1..=parameters.threshold).collect();
    let sign_id = rng::get_rng().random::<[u8; 32]>();
    let message_to_sign = dkls23_core::utilities::hashes::tagged_hash(b"test-sign", &[b"msg"]);

    // Build SignData per party and create sessions
    let mut sessions = BTreeMap::new();
    let mut phase1_outputs: BTreeMap<u8, PhaseOutput> = BTreeMap::new();
    for &i in &executing {
        let counterparties: Vec<PartyIndex> = executing
            .iter()
            .filter(|&&j| j != i)
            .map(|&j| PartyIndex::new(j).unwrap())
            .collect();
        let data = SignData {
            sign_id: sign_id.to_vec(),
            counterparties: counterparties.clone(),
            message_hash: message_to_sign,
        };
        let (session, transmit) =
            dkls23_core::SignSession::new(&parties[(i - 1) as usize], data).unwrap();
        sessions.insert(i, session);

        // Frame transmit messages into PhaseOutput for sender i
        let mut out = PhaseOutput::new();
        for msg in transmit {
            out.add_p2p(msg.parties.receiver.as_u8(), &msg).unwrap();
        }
        phase1_outputs.insert(i, out);
    }

    // Round1 routing: for each receiver assemble PhaseInput and call phase2
    let mut phase2_outputs: BTreeMap<u8, Vec<PhaseOutput>> = BTreeMap::new();

    for &recv in &executing {
        let input = assemble_input_for_receiver(&phase1_outputs, recv);
        // collect received TransmitPhase1to2's by decoding from PhaseInput
        let mut recv_msgs: Vec<TransmitPhase1to2> = Vec::new();
        for &sender in &executing {
            if sender == recv {
                continue;
            }
            let msg: TransmitPhase1to2 = input.get_p2p(sender).unwrap();
            recv_msgs.push(msg);
        }

        // call phase2 on the appropriate session
        let session = sessions.get_mut(&recv).unwrap();
        let transmit2 = session.phase2(&recv_msgs).unwrap();

        // frame transmit2 messages per this sender
        let mut out = PhaseOutput::new();
        for msg in transmit2 {
            out.add_p2p(msg.parties.receiver.as_u8(), &msg).unwrap();
        }
        phase2_outputs.insert(recv, vec![out]);
    }

    // Round2 routing: collect all phase2 outputs per sender to prepare inputs for phase3
    let mut sender_outputs_round2: Vec<PhaseOutput> = Vec::new();
    for &s in &executing {
        let outputs = phase2_outputs.get(&s).unwrap();
        // flatten (only 1 entry per sender here)
        sender_outputs_round2.push(outputs[0].clone());
    }

    // For each receiver, assemble received TransmitPhase2to3 and call phase3
    let mut broadcasts_round3: Vec<PhaseOutput> = Vec::new();
    for &recv in &executing {
        // assemble PhaseInput from vector of sender outputs (these outputs correspond to executing parties)
        let mut send_map: BTreeMap<u8, PhaseOutput> = BTreeMap::new();
        for (idx, &s) in executing.iter().enumerate() {
            send_map.insert(s, sender_outputs_round2[idx].clone());
        }
        let input = assemble_input_for_receiver(&send_map, recv);
        let mut recv_msgs: Vec<TransmitPhase2to3<Secp256k1>> = Vec::new();
        for &sender in &executing {
            if sender == recv {
                continue;
            }
            let msg: TransmitPhase2to3<Secp256k1> = input.get_p2p(sender).unwrap();
            recv_msgs.push(msg);
        }
        let session = sessions.get_mut(&recv).unwrap();
        let broadcast = session.phase3(&recv_msgs).unwrap();

        let mut out = PhaseOutput::new();
        out.add_broadcast(&broadcast).unwrap();
        broadcasts_round3.push(out);
    }

    // Round3 routing: for each party assemble broadcast inputs and call phase4 on one session to obtain signature
    // broadcasts_round3 is a Vec aligned with executing ordering; build map for decoding
    let mut broadcast_map: BTreeMap<u8, PhaseOutput> = BTreeMap::new();
    for (idx, &s) in executing.iter().enumerate() {
        broadcast_map.insert(s, broadcasts_round3[idx].clone());
    }
    let first = executing[0];
    let input = assemble_input_for_receiver(&broadcast_map, first);
    let mut broadcasts: Vec<Broadcast3to4<Secp256k1>> = Vec::new();
    for &sender in &executing {
        let b: Broadcast3to4<Secp256k1> = input.get_broadcast(sender).unwrap();
        broadcasts.push(b);
    }

    // finalize: pick one session and call phase4
    let session = sessions.remove(&first).unwrap();
    let signature = session.phase4(&broadcasts, true).unwrap();

    // verify signature non-trivial
    assert_ne!(signature.r, [0u8; 32]);
    assert_ne!(signature.s, [0u8; 32]);
}

#[test]
fn e2e_refresh_using_phaseio() {
    // Use re_key to prepare parties and then run the complete refresh protocol
    let threshold = rng::get_rng().random_range(2..=4);
    let offset = rng::get_rng().random_range(0..=2);
    let parameters = Parameters {
        threshold,
        share_count: threshold + offset,
    };
    let session_id = rng::get_rng().random::<[u8; SESSION_ID_LEN]>();

    // fixed secret
    let secret_key = k256::Scalar::reduce(&k256::U256::from_be_hex(
        "0249815B0D7E186DB61E7A6AAD6226608BB1C48B309EA8903CAB7A7283DA64A5",
    ));
    let (mut parties, _pkg) =
        re_key::<Secp256k1>(&parameters, &session_id, &secret_key, None, |_| {
            String::new()
        });

    let n = parties.len();
    // Phase1 (refresh): each party computes new polynomial fragments (constant term=0)
    let mut fragments: Vec<Vec<k256::Scalar>> = Vec::with_capacity(n);
    for p in &parties {
        fragments.push(p.refresh_complete_phase1());
    }

    // transpose fragments into per-party-received lists
    let mut poly_fragments = vec![Vec::<k256::Scalar>::with_capacity(n); n];
    for row in fragments {
        for j in 0..parameters.share_count as usize {
            poly_fragments[j].push(row[j]);
        }
    }

    // Phase2: each party runs refresh_complete_phase2 -> emits correction_value, proof_commitment, zero_keep map & zero_transmit (p2p)
    let mut per_sender_outputs: BTreeMap<u8, PhaseOutput> = BTreeMap::new();
    let mut proof_commitments: Vec<ProofCommitment<Secp256k1>> = Vec::with_capacity(n);
    let mut zero_tx_per_sender: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    let mut zero_keep_per_sender: Vec<
        BTreeMap<PartyIndex, dkls23_core::protocols::dkg::KeepInitZeroSharePhase2to3>,
    > = Vec::with_capacity(n);
    let mut correction_values: Vec<k256::Scalar> = Vec::with_capacity(n);

    for (i, p) in parties.iter_mut().enumerate() {
        let sender_id = (i as u8) + 1;
        let (correction_value, proof_commitment, zero_keep, zero_transmit) =
            p.refresh_complete_phase2(&session_id, &poly_fragments[i]);
        correction_values.push(correction_value);
        proof_commitments.push(proof_commitment.clone());

        // frame proof commit and p2p
        let mut out = PhaseOutput::new();
        out.add_broadcast(&proof_commitment).unwrap();
        for msg in &zero_transmit {
            out.add_p2p(msg.parties.receiver.as_u8(), msg).unwrap();
        }
        per_sender_outputs.insert(sender_id, out);

        zero_tx_per_sender.push(zero_transmit);
        zero_keep_per_sender.push(zero_keep);
    }

    // Round2 routing: collect zero-share p2p for each receiver
    let mut zero_received_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    for recv in 1..=parameters.share_count {
        let input = assemble_input_for_receiver(&per_sender_outputs, recv as u8);
        let mut row = Vec::new();
        for sender in 1..=parameters.share_count {
            if sender == recv {
                continue;
            }
            if let Ok(msg) = input.get_p2p::<TransmitInitZeroSharePhase2to4>(sender) {
                row.push(msg);
            } else {
                panic!(
                    "Missing p2p zero transmit from {} for recv {}",
                    sender, recv
                );
            }
        }
        zero_received_2to4.push(row);
    }

    // Phase3: call refresh_complete_phase3 with the zero_keep produced in phase2 for each party
    let mut per_sender_outputs_3: BTreeMap<u8, PhaseOutput> = BTreeMap::new();
    // Keep zero_keep and mul_keep per sender for routing to phase4
    let mut zero_keep3_per_sender: Vec<
        BTreeMap<PartyIndex, dkls23_core::protocols::dkg::KeepInitZeroSharePhase3to4>,
    > = Vec::with_capacity(n);
    let mut mul_keep3_per_sender: Vec<
        BTreeMap<PartyIndex, dkls23_core::protocols::dkg::KeepInitMulPhase3to4<Secp256k1>>,
    > = Vec::with_capacity(n);
    let mut zero_tx3_per_sender: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mul_tx3_per_sender: Vec<Vec<TransmitInitMulPhase3to4<Secp256k1>>> =
        Vec::with_capacity(n);

    for (i, p) in parties.iter_mut().enumerate() {
        let sender_id = (i as u8) + 1;
        let (zero_keep_3to4, zero_transmit_3to4, mul_keep, mul_transmit_3to4) =
            p.refresh_complete_phase3(&session_id, &zero_keep_per_sender[i]);

        // frame p2p messages into per-sender PhaseOutput
        let mut out = PhaseOutput::new();
        for msg in &zero_transmit_3to4 {
            out.add_p2p(msg.parties.receiver.as_u8(), msg).unwrap();
        }
        for msg in &mul_transmit_3to4 {
            out.add_p2p(msg.parties.receiver.as_u8(), msg).unwrap();
        }
        per_sender_outputs_3.insert(sender_id, out);

        zero_keep3_per_sender.push(zero_keep_3to4);
        mul_keep3_per_sender.push(mul_keep);
        zero_tx3_per_sender.push(zero_transmit_3to4);
        mul_tx3_per_sender.push(mul_transmit_3to4);
    }

    // Round3 routing: collect zero/mul p2p messages intended for each receiver (decode from PhaseInput)
    let mut zero_received_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4<Secp256k1>>> =
        Vec::with_capacity(n);

    for recv_idx in 1..=parameters.share_count {
        let pi = recv_idx as u8;
        let input = assemble_input_for_receiver(&per_sender_outputs_3, pi);

        // Collect p2p zero and mul messages intended for this receiver by decoding from PhaseInput
        let mut zero_row: Vec<TransmitInitZeroSharePhase3to4> = Vec::new();
        let mut mul_row: Vec<TransmitInitMulPhase3to4<Secp256k1>> = Vec::new();
        for sender in 1..=parameters.share_count {
            if sender == pi {
                continue;
            }
            if let Ok(z) = input.get_p2p::<TransmitInitZeroSharePhase3to4>(sender) {
                zero_row.push(z);
            }
            if let Ok(m) = input.get_p2p::<TransmitInitMulPhase3to4<Secp256k1>>(sender) {
                mul_row.push(m);
            }
        }
        zero_received_3to4.push(zero_row);
        mul_received_3to4.push(mul_row);
    }

    // Round3 routing and Phase4: gather messages and complete refresh
    let mut refreshed_parties: Vec<dkls23_core::protocols::Party<Secp256k1>> =
        Vec::with_capacity(n);
    for (i, p) in parties.into_iter().enumerate() {
        // Build inputs for phase4 using collected keeps and routed transmissions
        let zero_kept_map = &zero_keep3_per_sender[i];
        let mul_kept_map = &mul_keep3_per_sender[i];
        let zero_recv2 = &zero_received_2to4[i];
        let zero_recv3 = &zero_received_3to4[i];
        let mul_recv = &mul_received_3to4[i];

        let result = p.refresh_complete_phase4(
            &session_id,
            &correction_values[i],
            &proof_commitments,
            zero_kept_map,
            zero_recv2,
            zero_recv3,
            mul_kept_map,
            mul_recv,
        );
        if let Ok(new_party) = result {
            refreshed_parties.push(new_party);
        }
    }

    // basic assertion: we obtained refreshed parties without panics
    assert_eq!(refreshed_parties.len(), n);
}

/// End-to-end resharing test with signing at each step.
///
/// Scenario:
/// ```text
/// Step 0 : DKG   2-of-2  {P1@1, P2@2}
///          → sign message 1 (both parties)
///
/// Step 1 : Reshare 2-of-2 → 2-of-3  add P3 at index 3
///          J = {P1@1, P2@2}; new set = {P1@1, P2@2, P3@3}
///          → sign message 2 with every 2-party combination
///
/// Step 2 : Reshare 2-of-3 → 2-of-3  replace P1 with P_new
///          J = {P2@2, P3@3}; new set = {P_new@1, P2@2, P3@3}
///          → sign message 3 with every 2-party combination
/// ```
///
/// At every step the group public key and chain code must remain identical.
#[test]
fn e2e_resharing_with_signing() {
    // ── Step 0: initial 2-of-2 DKG ──────────────────────────────────────────
    let params_2of2 = Parameters {
        threshold: 2,
        share_count: 2,
    };
    let sid0: [u8; SESSION_ID_LEN] = rng::get_rng().random();

    let sessions_0: Vec<DkgSession<Secp256k1>> = (0..2_u8)
        .map(|i| {
            DkgSession::new(
                params_2of2.clone(),
                PartyIndex::new(i + 1).unwrap(),
                sid0.to_vec(),
            )
        })
        .collect();
    let parties_0 = run_reshare_sessions(sessions_0);

    let group_pk = parties_0[0].pk;
    let chain_code = parties_0[0].derivation_data.chain_code;
    assert_eq!(
        parties_0[1].pk, group_pk,
        "DKG: both parties must share the same pk"
    );
    assert_eq!(
        parties_0[1].derivation_data.chain_code, chain_code,
        "DKG: both parties must share the same chain_code"
    );

    // Sign message 1 with the original 2-of-2 configuration.
    let msg1 = dkls23_core::utilities::hashes::tagged_hash(b"e2e-reshare", &[b"step0-message"]);
    sign_and_verify_reshare(&parties_0, &[1, 2], msg1);

    // ── Step 1: 2-of-2 → 2-of-3 (add P3) ───────────────────────────────────
    // J = {P1@1, P2@2}; P3 is brand-new (not in J).
    let params_2of3 = Parameters {
        threshold: 2,
        share_count: 3,
    };
    let sid1: [u8; SESSION_ID_LEN] = rng::get_rng().random();
    let j1 = vec![PartyIndex::new(1).unwrap(), PartyIndex::new(2).unwrap()];

    let sessions_1: Vec<DkgSession<Secp256k1>> = vec![
        // P1 stays at index 1.
        DkgSession::new_reshare_from_party(
            &parties_0[0],
            j1.clone(),
            params_2of3.clone(),
            PartyIndex::new(1).unwrap(),
            sid1.to_vec(),
        ),
        // P2 stays at index 2.
        DkgSession::new_reshare_from_party(
            &parties_0[1],
            j1.clone(),
            params_2of3.clone(),
            PartyIndex::new(2).unwrap(),
            sid1.to_vec(),
        ),
        // P3: brand-new device, receives index 3.
        DkgSession::new_reshare_as_new_party(
            group_pk,
            chain_code,
            params_2of3.clone(),
            PartyIndex::new(3).unwrap(),
            sid1.to_vec(),
        ),
    ];
    let parties_1 = run_reshare_sessions(sessions_1);

    // Verify pk and chain_code are preserved across all 3 parties.
    for p in &parties_1 {
        assert_eq!(
            p.pk, group_pk,
            "Step 1: pk must be preserved (party {})",
            p.party_index
        );
        assert_eq!(
            p.derivation_data.chain_code, chain_code,
            "Step 1: chain_code must be preserved (party {})",
            p.party_index
        );
    }

    // Sign message 2 using every valid 2-of-3 combination.
    let msg2 = dkls23_core::utilities::hashes::tagged_hash(b"e2e-reshare", &[b"step1-message"]);
    sign_and_verify_reshare(&parties_1, &[1, 2], msg2);
    sign_and_verify_reshare(&parties_1, &[1, 3], msg2); // P3 (new party) can sign
    sign_and_verify_reshare(&parties_1, &[2, 3], msg2);

    // ── Step 2: 2-of-3 → 2-of-3, replace P1 with P_new ─────────────────────
    // P1 is removed from the active set.  P_new takes over index 1.
    // J = {P2@2, P3@3} — exactly threshold = 2 parties, so both must participate.
    // parties_1 indexing: [0] = P1@1 (removed), [1] = P2@2, [2] = P3@3.
    let sid2: [u8; SESSION_ID_LEN] = rng::get_rng().random();
    let j2 = vec![PartyIndex::new(2).unwrap(), PartyIndex::new(3).unwrap()];

    let sessions_2: Vec<DkgSession<Secp256k1>> = vec![
        // P_new: joins for the first time, gets index 1.
        DkgSession::new_reshare_as_new_party(
            group_pk,
            chain_code,
            params_2of3.clone(),
            PartyIndex::new(1).unwrap(),
            sid2.to_vec(),
        ),
        // P2 continues at index 2.
        DkgSession::new_reshare_from_party(
            &parties_1[1],
            j2.clone(),
            params_2of3.clone(),
            PartyIndex::new(2).unwrap(),
            sid2.to_vec(),
        ),
        // P3 continues at index 3.
        DkgSession::new_reshare_from_party(
            &parties_1[2],
            j2.clone(),
            params_2of3.clone(),
            PartyIndex::new(3).unwrap(),
            sid2.to_vec(),
        ),
    ];
    let parties_2 = run_reshare_sessions(sessions_2);

    // Verify pk and chain_code are preserved.
    for p in &parties_2 {
        assert_eq!(
            p.pk, group_pk,
            "Step 2: pk must be preserved (party {})",
            p.party_index
        );
        assert_eq!(
            p.derivation_data.chain_code, chain_code,
            "Step 2: chain_code must be preserved (party {})",
            p.party_index
        );
    }

    // Sign message 3 using the new configuration {P_new@1, P2@2, P3@3}.
    // Every 2-of-3 combination must work, including the brand-new P_new.
    let msg3 = dkls23_core::utilities::hashes::tagged_hash(b"e2e-reshare", &[b"step2-message"]);
    sign_and_verify_reshare(&parties_2, &[1, 2], msg3); // P_new + P2
    sign_and_verify_reshare(&parties_2, &[1, 3], msg3); // P_new + P3
    sign_and_verify_reshare(&parties_2, &[2, 3], msg3); // P2 + P3 (P_new excluded)
}

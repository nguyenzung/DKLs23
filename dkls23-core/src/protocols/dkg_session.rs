use std::collections::BTreeMap;
use std::fmt;

use zeroize::Zeroize;

use crate::curve::DklsCurve;
use crate::protocols::derivation::ChainCode;
use crate::protocols::dkg::{
    self, BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4, KeepInitMulPhase3to4,
    KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4, ProofCommitment, SessionData,
    TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
    UniqueKeepDerivationPhase2to3,
};
use crate::protocols::{Abort, AbortReason, Parameters, Party, PartyIndex, PublicKeyPackage};

pub struct DkgSession<C: DklsCurve> {
    data: SessionData<C>,
    poly_point: Option<C::Scalar>,
    proof_commitment: Option<ProofCommitment<C>>,
    zero_kept_2to3: Option<BTreeMap<PartyIndex, KeepInitZeroSharePhase2to3>>,
    bip_kept_2to3: Option<UniqueKeepDerivationPhase2to3>,
    zero_kept_3to4: Option<BTreeMap<PartyIndex, KeepInitZeroSharePhase3to4>>,
    mul_kept_3to4: Option<BTreeMap<PartyIndex, KeepInitMulPhase3to4<C>>>,
}

impl<C: DklsCurve> DkgSession<C> {
    /// Creates a fresh DKG session (not a resharing).
    #[must_use]
    pub fn new(parameters: Parameters, party_index: PartyIndex, session_id: Vec<u8>) -> Self {
        DkgSession {
            data: SessionData {
                parameters,
                party_index,
                session_id,
                is_reshare: false,
                old_threshold: None,
                old_participants: None,
                old_pk: None,
                old_share: None,
                old_party_index: None,
                old_chain_code: None,
            },
            poly_point: None,
            proof_commitment: None,
            zero_kept_2to3: None,
            bip_kept_2to3: None,
            zero_kept_3to4: None,
            mul_kept_3to4: None,
        }
    }

    /// Creates a resharing session for an **old party** that already holds a [`Party<C>`].
    ///
    /// # Arguments
    ///
    /// * `old_party` — the existing party whose share `s_i` will be used in Phase 1.
    /// * `old_participants` — the explicit subset J of old parties taking part in
    ///   this resharing run.  This **must** be supplied by the coordinator; `Party<C>`
    ///   does not know which subset was chosen.
    /// * `new_parameters` — threshold and share count for the new configuration.
    /// * `new_party_index` — this party's index in the new configuration.
    /// * `session_id` — fresh session identifier.
    #[must_use]
    pub fn new_reshare_from_party(
        old_party: &Party<C>,
        old_participants: Vec<PartyIndex>,
        new_parameters: Parameters,
        new_party_index: PartyIndex,
        session_id: Vec<u8>,
    ) -> Self {
        DkgSession {
            data: SessionData {
                parameters: new_parameters,
                party_index: new_party_index,
                session_id,
                is_reshare: true,
                old_threshold: Some(old_party.parameters.threshold),
                old_participants: Some(old_participants),
                old_pk: Some(old_party.pk),
                // Copy the old share — it will be zeroized immediately after Phase 1 uses it.
                old_share: Some(old_party.poly_point),
                // Fix A: Store the OLD party index so phase1 can find it in old_participants,
                // even when old_index ≠ new_index (e.g. P2 at old idx=2 reassigned to new idx=3).
                old_party_index: Some(old_party.party_index),
                // Fix B: Preserve the chain code so BIP-32 derived addresses stay stable.
                old_chain_code: Some(old_party.derivation_data.chain_code),
            },
            poly_point: None,
            proof_commitment: None,
            zero_kept_2to3: None,
            bip_kept_2to3: None,
            zero_kept_3to4: None,
            mul_kept_3to4: None,
        }
    }

    /// Creates a resharing session for a **new party** that has no previous [`Party<C>`].
    ///
    /// Such a party does not belong to J (no old share), so `a_{i,0}` will be forced
    /// to zero automatically in Phase 1.
    ///
    /// # Arguments
    ///
    /// * `old_pk` — the existing group public key, obtained from a trusted source
    ///   (e.g. a signed [`PublicKeyPackage`]).  It is kept until Phase 4 to verify
    ///   `new_pk == old_pk`.
    /// * `old_chain_code` — the existing group chain code (public BIP-32 value, available
    ///   from any xpub or from existing parties).  It **must** match the chain code held by
    ///   the old parties so that after resharing every party — old and new alike — derives
    ///   the same child keys and produces consistent multiplication session IDs during signing.
    /// * `new_parameters`, `new_party_index`, `session_id` — same as [`new`].
    #[must_use]
    pub fn new_reshare_as_new_party(
        old_pk: C::AffinePoint,
        old_chain_code: ChainCode,
        new_parameters: Parameters,
        new_party_index: PartyIndex,
        session_id: Vec<u8>,
    ) -> Self {
        DkgSession {
            data: SessionData {
                parameters: new_parameters,
                party_index: new_party_index,
                session_id,
                is_reshare: true,
                old_threshold: None,
                old_participants: None, // Not in J → a_{i,0} = 0 automatically.
                old_pk: Some(old_pk),
                old_share: None,
                old_party_index: None,
                // Supply the old chain code so that after Phase 4 this new party's
                // derivation_data.chain_code equals that of the old parties.
                // Without this, multiplication session IDs diverge between old and new
                // parties and signing fails.
                old_chain_code: Some(old_chain_code),
            },
            poly_point: None,
            proof_commitment: None,
            zero_kept_2to3: None,
            bip_kept_2to3: None,
            zero_kept_3to4: None,
            mul_kept_3to4: None,
        }
    }

    /// Phase 1: generate polynomial fragments to send to each counterparty.
    ///
    /// For resharing sessions, this also validates that `old_share` is present
    /// when required, and zeroizes it immediately after use.
    ///
    /// # Errors
    ///
    /// Returns `Err` if this is a resharing session and the resharing invariants
    /// are violated (missing share, insufficient participants, …).
    pub fn phase1(&mut self) -> Result<Vec<C::Scalar>, Abort> {
        let result = dkg::phase1::<C>(&self.data)?;

        // Zeroize old_share immediately — it is no longer needed after Phase 1.
        if let Some(ref mut s) = self.data.old_share {
            s.zeroize();
        }
        self.data.old_share = None;

        Ok(result)
    }

    pub fn phase2(
        &mut self,
        poly_fragments: &[C::Scalar],
    ) -> Result<
        (
            ProofCommitment<C>,
            Vec<TransmitInitZeroSharePhase2to4>,
            BroadcastDerivationPhase2to4,
        ),
        Abort,
    > {
        if self.poly_point.is_some() {
            return Err(Abort::recoverable(
                self.data.party_index,
                AbortReason::PhaseCalledOutOfOrder {
                    phase: "phase2 already called on this session".into(),
                },
            ));
        }

        let (poly_point, proof_commitment, zero_keep, zero_transmit, bip_keep, bip_broadcast) =
            dkg::phase2::<C>(&self.data, poly_fragments);

        self.poly_point = Some(poly_point);
        self.proof_commitment = Some(proof_commitment.clone());
        self.zero_kept_2to3 = Some(zero_keep);
        self.bip_kept_2to3 = Some(bip_keep);

        Ok((proof_commitment, zero_transmit, bip_broadcast))
    }

    pub fn phase3(
        &mut self,
    ) -> Result<
        (
            Vec<TransmitInitZeroSharePhase3to4>,
            Vec<TransmitInitMulPhase3to4<C>>,
            BroadcastDerivationPhase3to4,
        ),
        Abort,
    > {
        let zero_kept = self.zero_kept_2to3.as_ref().ok_or_else(|| {
            Abort::recoverable(
                self.data.party_index,
                AbortReason::PhaseCalledOutOfOrder {
                    phase: "phase3 called before phase2".into(),
                },
            )
        })?;
        let bip_kept = self.bip_kept_2to3.as_ref().ok_or_else(|| {
            Abort::recoverable(
                self.data.party_index,
                AbortReason::PhaseCalledOutOfOrder {
                    phase: "phase3 called before phase2".into(),
                },
            )
        })?;

        let (zero_keep_3to4, zero_transmit, mul_keep, mul_transmit, bip_broadcast) =
            dkg::phase3::<C>(&self.data, zero_kept, bip_kept);

        if let Some(ref mut map) = self.zero_kept_2to3 {
            for v in map.values_mut() {
                v.seed.zeroize();
                v.salt.zeroize();
            }
            map.clear();
        }
        self.zero_kept_2to3 = None;

        if let Some(ref mut bip) = self.bip_kept_2to3 {
            bip.aux_chain_code.zeroize();
            bip.cc_salt.zeroize();
        }
        self.bip_kept_2to3 = None;
        self.zero_kept_3to4 = Some(zero_keep_3to4);
        self.mul_kept_3to4 = Some(mul_keep);

        Ok((zero_transmit, mul_transmit, bip_broadcast))
    }

    pub fn phase4(
        self,
        proofs_commitments: &[ProofCommitment<C>],
        zero_received_phase2: &[TransmitInitZeroSharePhase2to4],
        zero_received_phase3: &[TransmitInitZeroSharePhase3to4],
        mul_received: &[TransmitInitMulPhase3to4<C>],
        bip_received_phase2: &BTreeMap<PartyIndex, BroadcastDerivationPhase2to4>,
        bip_received_phase3: &BTreeMap<PartyIndex, BroadcastDerivationPhase3to4>,
        address_fn: impl Fn(&C::AffinePoint) -> String,
    ) -> Result<(Party<C>, PublicKeyPackage<C>), Abort> {
        let poly_point = self.poly_point.as_ref().ok_or_else(|| {
            Abort::recoverable(
                self.data.party_index,
                AbortReason::PhaseCalledOutOfOrder {
                    phase: "phase4 called before phase2".into(),
                },
            )
        })?;
        let zero_kept = self.zero_kept_3to4.as_ref().ok_or_else(|| {
            Abort::recoverable(
                self.data.party_index,
                AbortReason::PhaseCalledOutOfOrder {
                    phase: "phase4 called before phase3".into(),
                },
            )
        })?;
        let mul_kept = self.mul_kept_3to4.as_ref().ok_or_else(|| {
            Abort::recoverable(
                self.data.party_index,
                AbortReason::PhaseCalledOutOfOrder {
                    phase: "phase4 called before phase3".into(),
                },
            )
        })?;

        let (mut new_party, pkg) = dkg::phase4::<C>(
            &self.data,
            poly_point,
            proofs_commitments,
            zero_kept,
            zero_received_phase2,
            zero_received_phase3,
            mul_kept,
            mul_received,
            bip_received_phase2,
            bip_received_phase3,
            address_fn,
        )?;

        // ── Resharing security check ────────────────────────────────────────
        // The new group public key MUST equal the old one.  If any old party
        // supplied a wrong a_{i,0}, the reconstructed key will differ and we
        // abort.  This mirrors how refresh_complete_phase4 checks == identity.
        if self.data.is_reshare {
            // Fix B: Restore the old chain code so that all BIP-32 derived
            // addresses remain stable after the key ceremony.  Without this,
            // the DKG BIP-32 protocol would assign a freshly-randomised chain
            // code to the new party set, breaking wallet address continuity.
            if let Some(old_chain_code) = self.data.old_chain_code {
                new_party.derivation_data.chain_code = old_chain_code;
            }

            let old_pk = self.data.old_pk.ok_or_else(|| {
                Abort::recoverable(self.data.party_index, AbortReason::TrivialPublicKey)
            })?;
            if new_party.pk != old_pk {
                return Err(Abort::recoverable(
                    self.data.party_index,
                    AbortReason::PolynomialInconsistency,
                ));
            }
        }

        Ok((new_party, pkg))
    }
}

impl<C: DklsCurve> fmt::Debug for DkgSession<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = if self.mul_kept_3to4.is_some() {
            "phase3 complete"
        } else if self.poly_point.is_some() {
            "phase2 complete"
        } else {
            "initialized"
        };
        f.debug_struct("DkgSession")
            .field("party_index", &self.data.party_index)
            .field("threshold", &self.data.parameters.threshold)
            .field("share_count", &self.data.parameters.share_count)
            .field("is_reshare", &self.data.is_reshare)
            .field("state", &phase)
            .finish()
    }
}

impl<C: DklsCurve> Zeroize for DkgSession<C>
where
    C::Scalar: Zeroize,
{
    fn zeroize(&mut self) {
        // Zeroize SessionData (covers session_id and old_share).
        self.data.zeroize();

        if let Some(ref mut pp) = self.poly_point {
            pp.zeroize();
        }
        self.poly_point = None;
        self.proof_commitment = None;

        if let Some(ref mut map) = self.zero_kept_2to3 {
            for v in map.values_mut() {
                v.seed.zeroize();
                v.salt.zeroize();
            }
            map.clear();
        }
        self.zero_kept_2to3 = None;

        if let Some(ref mut bip) = self.bip_kept_2to3 {
            bip.aux_chain_code.zeroize();
            bip.cc_salt.zeroize();
        }
        self.bip_kept_2to3 = None;

        if let Some(ref mut map) = self.zero_kept_3to4 {
            for v in map.values_mut() {
                v.seed.zeroize();
            }
            map.clear();
        }
        self.zero_kept_3to4 = None;

        if let Some(ref mut map) = self.mul_kept_3to4 {
            for v in map.values_mut() {
                v.ot_sender.s.zeroize();
                v.ot_receiver.seed.zeroize();
                v.nonce.zeroize();
                v.vec_r.zeroize();
                v.correlation.zeroize();
            }
            map.clear();
        }
        self.mul_kept_3to4 = None;
    }
}

impl<C: DklsCurve> Drop for DkgSession<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::AbortReason;
    use crate::utilities::rng;
    use k256::Secp256k1;
    use rand::RngExt;

    const SESSION_ID_LEN: usize = 32;

    #[test]
    fn test_dkg_session_full_flow() {
        let threshold = rng::get_rng().random_range(2..=5);
        let offset = rng::get_rng().random_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        };
        let session_id = rng::get_rng().random::<[u8; SESSION_ID_LEN]>();

        let n = parameters.share_count as usize;

        // Create sessions for each party.
        let mut sessions: Vec<DkgSession<Secp256k1>> = (0..parameters.share_count)
            .map(|i| {
                DkgSession::new(
                    parameters.clone(),
                    PartyIndex::new(i + 1).unwrap(),
                    session_id.to_vec(),
                )
            })
            .collect();

        // Phase 1
        let mut dkg_1: Vec<Vec<k256::Scalar>> = Vec::with_capacity(n);
        for session in sessions.iter_mut() {
            dkg_1.push(session.phase1().unwrap());
        }

        // Communication round 1: transpose poly fragments.
        let mut poly_fragments = vec![Vec::<k256::Scalar>::with_capacity(n); n];
        for row in dkg_1 {
            for j in 0..parameters.share_count {
                poly_fragments[j as usize].push(row[j as usize]);
            }
        }

        // Phase 2
        let mut proofs_commitments: Vec<ProofCommitment<Secp256k1>> = Vec::with_capacity(n);
        let mut zero_transmit_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
            Vec::with_capacity(n);
        let mut bip_broadcast_2to4: BTreeMap<PartyIndex, BroadcastDerivationPhase2to4> =
            BTreeMap::new();

        for (i, session) in sessions.iter_mut().enumerate() {
            let (proof_commitment, zero_transmit, bip_broadcast) =
                session.phase2(&poly_fragments[i]).unwrap();

            proofs_commitments.push(proof_commitment);
            zero_transmit_2to4.push(zero_transmit);
            bip_broadcast_2to4.insert(PartyIndex::new(i as u8 + 1).unwrap(), bip_broadcast);
        }

        // Communication round 2: route zero-share messages.
        let mut zero_received_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
            Vec::with_capacity(n);
        for i in 1..=parameters.share_count {
            let pi = PartyIndex::new(i).unwrap();
            let mut row = Vec::with_capacity(n - 1);
            for party in &zero_transmit_2to4 {
                for message in party {
                    if message.parties.receiver == pi {
                        row.push(message.clone());
                    }
                }
            }
            zero_received_2to4.push(row);
        }

        // Phase 3
        let mut zero_transmit_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
            Vec::with_capacity(n);
        let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4<Secp256k1>>> =
            Vec::with_capacity(n);
        let mut bip_broadcast_3to4: BTreeMap<PartyIndex, BroadcastDerivationPhase3to4> =
            BTreeMap::new();

        for (i, session) in sessions.iter_mut().enumerate() {
            let (zero_transmit, mul_transmit, bip_broadcast) = session.phase3().unwrap();

            zero_transmit_3to4.push(zero_transmit);
            mul_transmit_3to4.push(mul_transmit);
            bip_broadcast_3to4.insert(PartyIndex::new(i as u8 + 1).unwrap(), bip_broadcast);
        }

        // Communication round 3: route zero-share and mul messages.
        let mut zero_received_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
            Vec::with_capacity(n);
        let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4<Secp256k1>>> =
            Vec::with_capacity(n);
        for i in 1..=parameters.share_count {
            let pi = PartyIndex::new(i).unwrap();
            let mut zero_row = Vec::with_capacity(n - 1);
            for party in &zero_transmit_3to4 {
                for message in party {
                    if message.parties.receiver == pi {
                        zero_row.push(message.clone());
                    }
                }
            }
            zero_received_3to4.push(zero_row);

            let mut mul_row = Vec::with_capacity(n - 1);
            for party in &mul_transmit_3to4 {
                for message in party {
                    if message.parties.receiver == pi {
                        mul_row.push(message.clone());
                    }
                }
            }
            mul_received_3to4.push(mul_row);
        }

        // Phase 4
        let mut parties: Vec<Party<Secp256k1>> = Vec::with_capacity(n);
        for (i, session) in sessions.into_iter().enumerate() {
            let (party, _pkg) = session
                .phase4(
                    &proofs_commitments,
                    &zero_received_2to4[i],
                    &zero_received_3to4[i],
                    &mul_received_3to4[i],
                    &bip_broadcast_2to4,
                    &bip_broadcast_3to4,
                    |_| String::new(),
                )
                .unwrap_or_else(|abort| {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description())
                });
            parties.push(party);
        }

        let expected_pk = parties[0].pk;
        let expected_chain_code = parties[0].derivation_data.chain_code;
        for party in &parties {
            assert_eq!(expected_pk, party.pk);
            assert_eq!(expected_chain_code, party.derivation_data.chain_code);
        }
    }

    #[test]
    fn test_dkg_session_phase_ordering() {
        let parameters = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let session_id = rng::get_rng().random::<[u8; SESSION_ID_LEN]>();
        let pi = PartyIndex::new(1).unwrap();

        // phase3 before phase2
        let mut session = DkgSession::<Secp256k1>::new(parameters.clone(), pi, session_id.to_vec());
        let result = session.phase3();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().reason,
            AbortReason::PhaseCalledOutOfOrder { ref phase } if phase.contains("phase3 called before phase2")
        ));

        // phase4 before phase2
        let session = DkgSession::<Secp256k1>::new(parameters.clone(), pi, session_id.to_vec());
        let result = session.phase4(
            &[],
            &[],
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeMap::new(),
            |_| String::new(),
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().reason,
            AbortReason::PhaseCalledOutOfOrder { ref phase } if phase.contains("phase4 called before phase2")
        ));

        // phase4 after phase2 but before phase3
        let mut session = DkgSession::<Secp256k1>::new(parameters, pi, session_id.to_vec());
        let fragments = session.phase1().unwrap();
        session.phase2(&fragments).unwrap();
        let result = session.phase4(
            &[],
            &[],
            &[],
            &[],
            &BTreeMap::new(),
            &BTreeMap::new(),
            |_| String::new(),
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().reason,
            AbortReason::PhaseCalledOutOfOrder { ref phase } if phase.contains("phase4 called before phase3")
        ));
    }

    #[test]
    fn test_dkg_session_double_phase2() {
        let parameters = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let session_id = rng::get_rng().random::<[u8; SESSION_ID_LEN]>();
        let pi = PartyIndex::new(1).unwrap();

        let mut session = DkgSession::<Secp256k1>::new(parameters.clone(), pi, session_id.to_vec());

        let fragments = session.phase1().unwrap();
        session.phase2(&fragments).unwrap();

        let result = session.phase2(&fragments);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().reason,
            AbortReason::PhaseCalledOutOfOrder { .. }
        ));
    }

    // ── Resharing tests ───────────────────────────────────────────────────────

    /// Helper: run a full DKG and return all parties.
    fn run_full_dkg(parameters: Parameters, session_id: &[u8]) -> Vec<Party<Secp256k1>> {
        let sessions: Vec<DkgSession<Secp256k1>> = (0..parameters.share_count)
            .map(|i| {
                DkgSession::new(
                    parameters.clone(),
                    PartyIndex::new(i + 1).unwrap(),
                    session_id.to_vec(),
                )
            })
            .collect();
        run_sessions(sessions)
    }

    /// Helper: run all DkgSession phases (1–4) and return the resulting parties.
    ///
    /// The sessions vector may contain any mix of regular / resharing sessions,
    /// all sharing the same `new_parameters` and using consecutive new indices
    /// matching their position in the vector (i.e. sessions[0] → index 1, etc.).
    fn run_sessions(mut sessions: Vec<DkgSession<Secp256k1>>) -> Vec<Party<Secp256k1>> {
        let n = sessions.len();

        // Phase 1
        let mut frags_matrix: Vec<Vec<k256::Scalar>> = Vec::with_capacity(n);
        for s in sessions.iter_mut() {
            frags_matrix.push(s.phase1().unwrap());
        }
        // Transpose: poly_frags[j] = all fragments destined for session j.
        let mut poly_frags = vec![Vec::<k256::Scalar>::with_capacity(n); n];
        for row in frags_matrix {
            for j in 0..n {
                poly_frags[j].push(row[j]);
            }
        }

        // Phase 2
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

        // Route phase-2 zero-share p2p messages.
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

        // Phase 3
        let mut zt3: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
        let mut mt3: Vec<Vec<TransmitInitMulPhase3to4<Secp256k1>>> = Vec::with_capacity(n);
        let mut bip3: BTreeMap<PartyIndex, BroadcastDerivationPhase3to4> = BTreeMap::new();

        for (i, s) in sessions.iter_mut().enumerate() {
            let (zt, mt, bb) = s.phase3().unwrap();
            let _ = i; // index not needed here
            zt3.push(zt);
            mt3.push(mt);
            bip3.insert(bb.sender_index, bb);
        }

        // Route phase-3 messages.
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

        // Phase 4
        sessions
            .into_iter()
            .enumerate()
            .map(|(i, s)| {
                let (party, _) = s
                    .phase4(&proofs, &zr2[i], &zr3[i], &mr3[i], &bip2, &bip3, |_| {
                        String::new()
                    })
                    .unwrap_or_else(|abort| {
                        panic!(
                            "Party {} phase4 aborted: {:?}",
                            abort.index,
                            abort.description()
                        )
                    });
                party
            })
            .collect()
    }

    /// Resharing chain test:
    ///
    /// ```text
    /// Step 0: DKG   2-of-2  {P1, P2}
    /// Step 1: reshare → 2-of-2  remove P2, add P3   (xóa party)
    ///         J = {P1, P2}; new set  = {P1→idx1, P3→idx2}
    ///         P2 runs as idx=3 in a temporary share_count=3 config and is then discarded.
    /// Step 2: reshare → 3-of-3  add P4              (thêm party)
    ///         J = {P1 at 1, P3 at 2}; new set = {P1→1, P3→2, P4→3}
    /// Step 3: reshare → 3-of-4  add P5              (thêm party)
    ///         J = {P1,P3,P4}; new set = {P1→1, P3→2, P4→3, P5→4}
    /// ```
    ///
    /// At every step the group public key must remain the same.
    #[test]
    fn test_resharing_chain() {
        // ── Step 0: initial DKG 2-of-2 ──────────────────────────────────────
        let params_2of2 = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let sid0: [u8; 32] = rng::get_rng().random();
        let initial = run_full_dkg(params_2of2.clone(), &sid0);
        let pk = initial[0].pk; // the public key that must survive every resharing
                                // The chain code is the same for all parties after DKG (Fix B ensures it stays the same
                                // through resharing). We'll reuse it when constructing new-party sessions.
        let chain_code = initial[0].derivation_data.chain_code;
        assert_eq!(initial[1].pk, pk);

        // ── Step 1: 2-of-2 → 2-of-2, remove P2, add P3 (xóa party) ─────────
        // Strategy: use a temporary share_count=3 configuration so every party
        // gets a distinct new index.  P1 → new idx 1, P3 (new) → new idx 2,
        // P2 (dropped) → new idx 3 (dummy slot, result discarded afterwards).
        let params_2of3_tmp = Parameters {
            threshold: 2,
            share_count: 3,
        };
        let sid1: [u8; 32] = rng::get_rng().random();
        let j1 = vec![PartyIndex::new(1).unwrap(), PartyIndex::new(2).unwrap()];

        let step1_sessions = vec![
            // P1: old party in J, keeps new index 1
            DkgSession::new_reshare_from_party(
                &initial[0],
                j1.clone(),
                params_2of3_tmp.clone(),
                PartyIndex::new(1).unwrap(),
                sid1.to_vec(),
            ),
            // P3: brand-new party, new index 2
            DkgSession::new_reshare_as_new_party(
                pk,
                chain_code,
                params_2of3_tmp.clone(),
                PartyIndex::new(2).unwrap(),
                sid1.to_vec(),
            ),
            // P2: old party in J, assigned to dummy index 3 (will be discarded)
            DkgSession::new_reshare_from_party(
                &initial[1],
                j1.clone(),
                params_2of3_tmp.clone(),
                PartyIndex::new(3).unwrap(),
                sid1.to_vec(),
            ),
        ];

        let step1_all = run_sessions(step1_sessions);
        // step1_all[0] = P1 (new idx 1), step1_all[1] = P3 (new idx 2), step1_all[2] = P2 dummy (discarded)
        for p in &step1_all {
            assert_eq!(p.pk, pk, "Step 1: pk must be preserved");
        }
        let step1_active = [&step1_all[0], &step1_all[1]]; // P1 and P3 only

        // ── Step 2: 2-of-3 (active: {P1,P3}) → 3-of-3, add P4 (thêm party) ──
        // J = {P1 at idx 1, P3 at idx 2}; old_threshold = 2 (from 2-of-3 config).
        let params_3of3 = Parameters {
            threshold: 3,
            share_count: 3,
        };
        let sid2: [u8; 32] = rng::get_rng().random();
        let j2 = vec![PartyIndex::new(1).unwrap(), PartyIndex::new(2).unwrap()];

        let step2_sessions = vec![
            DkgSession::new_reshare_from_party(
                step1_active[0],
                j2.clone(),
                params_3of3.clone(),
                PartyIndex::new(1).unwrap(),
                sid2.to_vec(),
            ),
            DkgSession::new_reshare_from_party(
                step1_active[1],
                j2.clone(),
                params_3of3.clone(),
                PartyIndex::new(2).unwrap(),
                sid2.to_vec(),
            ),
            // P4: brand-new party, new index 3
            DkgSession::new_reshare_as_new_party(
                pk,
                chain_code,
                params_3of3.clone(),
                PartyIndex::new(3).unwrap(),
                sid2.to_vec(),
            ),
        ];

        let step2_parties = run_sessions(step2_sessions);
        for p in &step2_parties {
            assert_eq!(p.pk, pk, "Step 2: pk must be preserved");
            assert_eq!(p.parameters.threshold, 3);
            assert_eq!(p.parameters.share_count, 3);
        }

        // ── Step 3: 3-of-3 → 3-of-4, add P5 (thêm party) ───────────────────
        // J = {1, 2, 3} (all 3 active parties); old_threshold = 3.
        let params_3of4 = Parameters {
            threshold: 3,
            share_count: 4,
        };
        let sid3: [u8; 32] = rng::get_rng().random();
        let j3 = vec![
            PartyIndex::new(1).unwrap(),
            PartyIndex::new(2).unwrap(),
            PartyIndex::new(3).unwrap(),
        ];

        let step3_sessions = vec![
            DkgSession::new_reshare_from_party(
                &step2_parties[0],
                j3.clone(),
                params_3of4.clone(),
                PartyIndex::new(1).unwrap(),
                sid3.to_vec(),
            ),
            DkgSession::new_reshare_from_party(
                &step2_parties[1],
                j3.clone(),
                params_3of4.clone(),
                PartyIndex::new(2).unwrap(),
                sid3.to_vec(),
            ),
            DkgSession::new_reshare_from_party(
                &step2_parties[2],
                j3.clone(),
                params_3of4.clone(),
                PartyIndex::new(3).unwrap(),
                sid3.to_vec(),
            ),
            // P5: brand-new party, new index 4
            DkgSession::new_reshare_as_new_party(
                pk,
                chain_code,
                params_3of4.clone(),
                PartyIndex::new(4).unwrap(),
                sid3.to_vec(),
            ),
        ];

        let step3_parties = run_sessions(step3_sessions);
        for p in &step3_parties {
            assert_eq!(p.pk, pk, "Step 3: pk must be preserved");
            assert_eq!(p.parameters.threshold, 3);
            assert_eq!(p.parameters.share_count, 4);
        }
    }

    /// Phase 1 of a resharing session must abort if a party belongs to J
    /// but has no old_share (not via `new_reshare_from_party`).
    #[test]
    fn test_resharing_phase1_aborts_when_in_j_but_no_share() {
        let new_params = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let sid: [u8; 32] = rng::get_rng().random();
        let j = vec![PartyIndex::new(1).unwrap(), PartyIndex::new(2).unwrap()];

        // Manually construct a session that claims to be in J but has no old_share.
        let mut session = DkgSession::<Secp256k1> {
            data: SessionData {
                parameters: new_params,
                party_index: PartyIndex::new(1).unwrap(),
                session_id: sid.to_vec(),
                is_reshare: true,
                old_threshold: Some(2),
                old_participants: Some(j),
                old_pk: None,
                old_share: None, // ← deliberately missing
                old_party_index: None,
                old_chain_code: None,
            },
            poly_point: None,
            proof_commitment: None,
            zero_kept_2to3: None,
            bip_kept_2to3: None,
            zero_kept_3to4: None,
            mul_kept_3to4: None,
        };

        let result = session.phase1();
        assert!(
            result.is_err(),
            "Should abort when in J but old_share is None"
        );
    }

    /// Phase 1 must abort when |J| < old_threshold.
    #[test]
    fn test_resharing_phase1_aborts_when_insufficient_participants() {
        let new_params = Parameters {
            threshold: 2,
            share_count: 2,
        };
        let sid: [u8; 32] = rng::get_rng().random();
        // Only 1 participant but threshold is 3.
        let j = vec![PartyIndex::new(1).unwrap()];

        let mut session = DkgSession::<Secp256k1> {
            data: SessionData {
                parameters: new_params,
                party_index: PartyIndex::new(2).unwrap(), // not in J → a_{i,0}=0 path
                session_id: sid.to_vec(),
                is_reshare: true,
                old_threshold: Some(3), // requires 3 but only 1 in J
                old_participants: Some(j),
                old_pk: None,
                old_share: None,
                old_party_index: None,
                old_chain_code: None,
            },
            poly_point: None,
            proof_commitment: None,
            zero_kept_2to3: None,
            bip_kept_2to3: None,
            zero_kept_3to4: None,
            mul_kept_3to4: None,
        };

        let result = session.phase1();
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err().reason,
                AbortReason::WrongCounterpartyCount { .. }
            ),
            "Should abort with WrongCounterpartyCount"
        );
    }
}

//! Generic (S)NARK verifier.

#![allow(clippy::type_complexity, clippy::too_many_arguments, clippy::upper_case_acronyms)]
#![deny(missing_debug_implementations, missing_docs, unsafe_code, rustdoc::all)]

pub mod cost;
pub mod loader;
pub mod pcs;
pub mod system;
pub mod util;
pub mod verifier;

use std::rc::Rc;
pub(crate) use halo2_base::halo2_proofs;
pub(crate) use halo2_proofs::halo2curves as halo2_curves;

pub use halo2_base;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::VerifyingKey;
use halo2_base::halo2_proofs::poly::commitment::ParamsProver;
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
#[cfg(feature = "loader_halo2")]
pub use halo2_ecc;
use crate::loader::evm::EvmLoader;
use crate::pcs::kzg::{Gwc19, KzgAs, KzgDecidingKey};
use crate::system::halo2::{compile, Config};
use crate::system::halo2::transcript::evm::EvmTranscript;
use crate::verifier::SnarkVerifier;

/// Error that could happen while verification.
#[derive(Clone, Debug)]
pub enum Error {
    /// Instances that don't match the amount specified in protocol.
    InvalidInstances,
    /// Protocol that is unreasonable for a verifier.
    InvalidProtocol(String),
    /// Assertion failure while verification.
    AssertionFailure(String),
    /// Transcript error.
    Transcript(std::io::ErrorKind, String),
}

type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

/// AZ verification outside EVM
pub fn aleph_zero_wants_to_verify(params: &ParamsKZG<Bn256>,
                                  vk: &VerifyingKey<G1Affine>) {
    let protocol = compile(params, vk, Config::kzg().with_num_instance(vec![1]));
    let vk: KzgDecidingKey<Bn256> = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(vec![1]);
    let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();
}

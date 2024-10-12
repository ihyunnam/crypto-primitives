/* Added for testing */
use crate::signature::*;
use ark_ec::{AdditiveGroup, CurveGroup};
use ark_ed_on_bls12_381::{EdwardsProjective as JubJub, Fr};
use ark_ff::Field;
use ark_std::{test_rng, UniformRand};
use blake2::Blake2s256 as Blake2s;
use crh::poseidon;
use schnorr::Schnorr;
use sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use signature::schnorr::constraints::ParametersVar;
mod signature;
mod crh;
mod sponge;

fn main() {
    // type ConstraintF = <<JubJub as CurveGroup>::BaseField as Field>::BasePrimeField;
    // let message = "Hi, I am a Schnorr signature!".as_bytes();
    // let rng = &mut test_rng();
    // let (ark, mds) = find_poseidon_ark_and_mds::<Fr> (252, 2, 8, 24, 0);        // ark_bn254::FrParameters::MODULUS_BITS = 255, bls381: 252
    // let poseidon_params = PoseidonConfig::<Fr>::new(8, 24, 31, mds, ark, 2, 1);
    // let poseidon_params_const = CRHParametersVar::new_variable(poseidon_params);
    // let rng = &mut test_rng();
    // let parameters = SignatureScheme::<Fr>::setup::<_>(rng).unwrap();
    // let parameters_const = ParametersVar::new_variable(parameters);
    // let (pk, sk) = SignatureScheme::<Fr>::keygen(&parameters, rng).unwrap();
    // let sig = SignatureScheme::<Fr>::sign(&poseidon_params, &parameters, &sk, &message, rng).unwrap();
    // assert!(SigVerifyGadget::<Schnorr<JubJub, Blake2s>, ConstraintF>::verify(&poseidon_params_const, &parameters_const, &pk_input, &message_wtns, &sig_wtns).unwrap());
}
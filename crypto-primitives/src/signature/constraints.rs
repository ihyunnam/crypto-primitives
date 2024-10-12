use ark_ff::{Field, PrimeField};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use ark_ed_on_bls12_381::Fr;
use crate::{signature::SignatureScheme, sponge::{poseidon::PoseidonConfig, Absorb}};
// use crate::crh::poseidon::constraints::CRHParametersVar;

pub trait SigVerifyGadget<S: SignatureScheme<Fr>, ConstraintF: Field> {
    type CRHParametersVar<F: PrimeField + Absorb>: AllocVar<PoseidonConfig<Fr>, Fr> + Clone;
    type ParametersVar: AllocVar<S::Parameters, ConstraintF> + Clone;

    type PublicKeyVar: ToBytesGadget<ConstraintF> + AllocVar<S::PublicKey, ConstraintF> + Clone;

    type SignatureVar: ToBytesGadget<ConstraintF> + AllocVar<S::Signature, ConstraintF> + Clone;

    fn verify(
        poseidon_params: &Self::CRHParametersVar<Fr>,
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        // TODO: Should we make this take in bytes or something different?
        message: &[UInt8<ConstraintF>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
}

pub trait SigRandomizePkGadget<S: SignatureScheme<Fr>, ConstraintF: Field> {
    type ParametersVar: AllocVar<S::Parameters, ConstraintF> + Clone;

    type PublicKeyVar: ToBytesGadget<ConstraintF>
        + EqGadget<ConstraintF>
        + AllocVar<S::PublicKey, ConstraintF>
        + Clone;

    fn randomize(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        randomness: &[UInt8<ConstraintF>],
    ) -> Result<Self::PublicKeyVar, SynthesisError>;
}
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::signature::{SigRandomizePkGadget, SigVerifyGadget};

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use ark_std::{borrow::Borrow, marker::PhantomData};

use crate::signature::schnorr::{Parameters, PublicKey, Schnorr};
use digest::Digest;

type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[derive(Clone)]
pub struct ParametersVar<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    generator: GC,
    _curve: PhantomData<C>,
}

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>")
)]
pub struct PublicKeyVar<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    pub_key: GC,
    #[doc(hidden)]
    _group: PhantomData<*const C>,
}

pub struct SchnorrRandomizePkGadget<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_gadget: PhantomData<*const GC>,
}

impl<C, GC, D> SigRandomizePkGadget<Schnorr<C, D>, ConstraintF<C>>
    for SchnorrRandomizePkGadget<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    D: Digest + Send + Sync,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    type ParametersVar = ParametersVar<C, GC>;
    type PublicKeyVar = PublicKeyVar<C, GC>;

    #[tracing::instrument(target = "r1cs", skip(parameters, public_key, randomness))]
    fn randomize(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        randomness: &[UInt8<ConstraintF<C>>],
    ) -> Result<Self::PublicKeyVar, SynthesisError> {
        let base = parameters.generator.clone();
        let randomness = randomness
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();
        let rand_pk = &public_key.pub_key + &base.scalar_mul_le(randomness.iter())?;
        Ok(PublicKeyVar {
            pub_key: rand_pk,
            _group: PhantomData,
        })
    }
}

impl<C, GC, D> AllocVar<Parameters<C, D>, ConstraintF<C>> for ParametersVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    D: Digest,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<Parameters<C, D>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let generator = GC::new_variable(cs, || f().map(|g| g.borrow().generator), mode)?;
        Ok(Self {
            generator,
            _curve: PhantomData,
        })
    }
}

impl<C, GC> AllocVar<PublicKey<C>, ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pub_key = GC::new_variable(cs, f, mode)?;
        Ok(Self {
            pub_key,
            _group: PhantomData,
        })
    }
}

impl<C, GC> EqGadget<ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        self.pub_key.is_eq(&other.pub_key)
    }

    #[inline]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_equal(&other.pub_key, condition)
    }

    #[inline]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_not_equal(&other.pub_key, condition)
    }
}

impl<C, GC> ToBytesGadget<ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn to_bytes_le(&self) -> Result<Vec<UInt8<ConstraintF<C>>>, SynthesisError> {
        self.pub_key.to_bytes_le()
    }
}


#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>")
)]
pub struct SignatureVar<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    pub(crate) prover_response: Vec<UInt8<ConstraintF<C>>>,
    pub(crate) verifier_challenge: Vec<UInt8<ConstraintF<C>>>,
    #[doc(hidden)]
    _group: PhantomData<GC>,
}

impl<C, GC> AllocVar<Signature<C>, ConstraintF<C>> for SignatureVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    fn new_variable<T: Borrow<Signature<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let response_bytes = to_bytes![val.borrow().prover_response].unwrap();
            let challenge_bytes = val.borrow().verifier_challenge;
            let mut prover_response = Vec::<UInt8<ConstraintF<C>>>::new();
            let mut verifier_challenge = Vec::<UInt8<ConstraintF<C>>>::new();
            for byte in &response_bytes {
                prover_response.push(UInt8::<ConstraintF<C>>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }
            for byte in &challenge_bytes {
                verifier_challenge.push(UInt8::<ConstraintF<C>>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }
            Ok(SignatureVar {
                prover_response,
                verifier_challenge,
                _group: PhantomData,
            })
        })
    }
}

impl<C, GC> ToBytesGadget<ConstraintF<C>> for SignatureVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF<C>>>, SynthesisError> {
        let prover_response_bytes = self.prover_response.to_bytes()?;
        let verifier_challenge_bytes = self.verifier_challenge.to_bytes()?;
        let mut bytes = Vec::<UInt8<ConstraintF<C>>>::new();
        bytes.extend(prover_response_bytes);
        bytes.extend(verifier_challenge_bytes);
        Ok(bytes)
    }
}

pub struct SchnorrSignatureVerifyGadget<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_gadget: PhantomData<*const GC>,
}

impl<C, GC, D> SigVerifyGadget<Schnorr<C, D>, ConstraintF<C>> for SchnorrSignatureVerifyGadget<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    type ParametersVar = ParametersVar<C, GC>;
    type PublicKeyVar = PublicKeyVar<C, GC>;
    type SignatureVar = SignatureVar<C, GC>;

    fn verify(
        poseidon_params: &PoseidonConfig<F>,
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<ConstraintF<C>>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        let prover_response = signature.prover_response.clone();
        let verifier_challenge = signature.verifier_challenge.clone();
        let mut claimed_prover_commitment = parameters
            .generator
            .scalar_mul_le(prover_response.to_bits_le()?.iter())?;
        let public_key_times_verifier_challenge = public_key
            .pub_key
            .scalar_mul_le(verifier_challenge.to_bits_le()?.iter())?;
        claimed_prover_commitment += &public_key_times_verifier_challenge;

        let mut hash_input = Vec::new();
        if let Some(salt) = parameters.salt.as_ref() {
            hash_input.extend_from_slice(salt);
        }
        hash_input.extend_from_slice(&public_key.pub_key.to_bytes()?);
        hash_input.extend_from_slice(&claimed_prover_commitment.to_bytes()?);
        hash_input.extend_from_slice(message);

        // let b2s_params = <Blake2sParametersVar as AllocVar<_, ConstraintF<C>>>::new_constant(
        //     ConstraintSystemRef::None,
        //     (),
        // )?;
        let hash_input_fe = F::from_le_bytes_mod_order(&hash_input);      // Poseidon takes F as input. Check if hash_input already LE?
        // let obtained_verifier_challenge = CRHGadget::<F>::evaluate(&poseidon_params, &[hash_input_fe])?.0;
        let obtained_verifier_challenge = CRHGadget::<F>::evaluate(&poseidon_params, &[hash_input_fe])?.to_bytes_le();

        obtained_verifier_challenge.is_eq(&verifier_challenge.to_vec())
    }
}
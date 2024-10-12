use ark_ed_on_bls12_381::Fr;
use crate::Error;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use crate::sponge::poseidon::PoseidonConfig;
use ark_std::hash::Hash;
use ark_std::rand::Rng;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

pub mod constraints;
pub use constraints::*;
pub mod schnorr;

pub trait SignatureScheme<F: PrimeField> {
    type Parameters: Clone + Send + Sync;
    type PublicKey: CanonicalSerialize + Hash + Eq + Clone + Default + Send + Sync;
    type SecretKey: CanonicalSerialize + Clone + Default;
    type Signature: Clone + Default + Send + Sync;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error>;

    fn sign<R: Rng>(
        poseidon_params: &PoseidonConfig<F>,
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, Error>;

    fn verify(
        poseidon_params: &PoseidonConfig<F>,
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error>;

    fn randomize_public_key(
        pp: &Self::Parameters,
        public_key: &Self::PublicKey,
        randomness: &[u8],
    ) -> Result<Self::PublicKey, Error>;

    fn randomize_signature(
        pp: &Self::Parameters,
        signature: &Self::Signature,
        randomness: &[u8],
    ) -> Result<Self::Signature, Error>;
}


#[cfg(test)]
mod test {
    use crate::{signature::*, sponge::poseidon::find_poseidon_ark_and_mds};
    use ark_ec::{AdditiveGroup, CurveGroup};
    use ark_ed_on_bls12_381::{EdwardsProjective as JubJub, Fr};
    use ark_ff::Field;
    use ark_std::{test_rng, UniformRand};
    use blake2::Blake2s256 as Blake2s;
    use constraints::SigVerifyGadget;
    use schnorr::Schnorr;

    fn sign_and_verify<S: SignatureScheme<Fr>>(message: &[u8]) {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr> (252, 2, 8, 24, 0);        // ark_bn254::FrParameters::MODULUS_BITS = 255, bls381: 252
        let poseidon_params = PoseidonConfig::<Fr>::new(8, 24, 31, mds, ark, 2, 1);
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&poseidon_params, &parameters, &sk, &message, rng).unwrap();
        assert!(S::verify(&poseidon_params, &parameters, &pk, &message, &sig).unwrap());
    }
    
    fn failed_verification<S: SignatureScheme<Fr>>(message: &[u8], bad_message: &[u8]) {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr> (252, 2, 8, 24, 0);        // ark_bn254::FrParameters::MODULUS_BITS = 255, bls381: 252
        let poseidon_params = PoseidonConfig::<Fr>::new(8, 24, 31, mds, ark, 2, 1);
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&poseidon_params, &parameters, &sk, message, rng).unwrap();
        assert!(!S::verify(&poseidon_params, &parameters, &pk, bad_message, &sig).unwrap());
    }
    
    fn randomize_and_verify<S: SignatureScheme<Fr>>(message: &[u8], randomness: &[u8]) {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr> (252, 2, 8, 24, 0);        // ark_bn254::FrParameters::MODULUS_BITS = 255, bls381: 252
        let poseidon_params = PoseidonConfig::<Fr>::new(8, 24, 31, mds, ark, 2, 1);
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&poseidon_params, &parameters, &sk, message, rng).unwrap();
        assert!(S::verify(&poseidon_params, &parameters, &pk, message, &sig).unwrap());
        let randomized_pk = S::randomize_public_key(&parameters, &pk, randomness).unwrap();
        let randomized_sig = S::randomize_signature(&parameters, &sig, randomness).unwrap();
        assert!(S::verify(&poseidon_params, &parameters, &randomized_pk, &message, &randomized_sig).unwrap());
    }
    
    #[test]
    fn schnorr_signature_test() {
        let message = "Hi, I am a Schnorr signature!";
        let rng = &mut test_rng();
        sign_and_verify::<schnorr::Schnorr<JubJub, Blake2s>>(message.as_bytes());
        failed_verification::<schnorr::Schnorr<JubJub, Blake2s>>(
            message.as_bytes(),
            "Bad message".as_bytes(),
        );
        let mut random_scalar_bytes = Vec::new();
        let random_scalar = <JubJub as AdditiveGroup>::Scalar::rand(rng);
        random_scalar
            .serialize_compressed(&mut random_scalar_bytes)
            .unwrap();
        randomize_and_verify::<schnorr::Schnorr<JubJub, Blake2s>>(
            message.as_bytes(),
            &random_scalar_bytes.as_slice(),
        );
    }
}

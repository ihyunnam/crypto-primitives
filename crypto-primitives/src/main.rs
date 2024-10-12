/* Added for testing */
use crate::signature::*;
use ark_ec::AdditiveGroup;
use ark_ed_on_bls12_381::{EdwardsProjective as JubJub, Fr};
use ark_std::{test_rng, UniformRand};
use blake2::Blake2s256 as Blake2s;
use crh::poseidon;
use sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
mod signature;
mod crh;
mod sponge;

fn main() {}
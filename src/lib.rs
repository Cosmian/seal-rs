#![allow(clippy::upper_case_acronyms)]

#[allow(
    dead_code,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case,
    clippy::unreadable_literal,
    clippy::redundant_static_lifetimes
)]
#[rustfmt::skip]
// FIXME: rustfmt only works if this file at least exists
mod seal_bindings;

mod batch_encoder;
mod cipher_text;
mod ckks_encoder;
mod context;
mod decryptor;
mod encryptor;
mod evaluator;
mod key_generator;
mod memory_pool_handle;
mod params;
mod plain_text;
mod small_modulus;

#[cfg(test)]
mod tests;

pub type SmallModulus = small_modulus::SmallModulus;
pub type Ciphertext = cipher_text::Ciphertext;
pub type Plaintext = plain_text::Plaintext;
pub type Params = params::Params;
pub type MemoryPoolHandle = memory_pool_handle::MemoryPoolHandle;
pub type KeyGenerator = key_generator::KeyGenerator;
pub type PublicKey = key_generator::PublicKey;
pub type SecretKey = key_generator::SecretKey;
pub type RelinearizationKeys = key_generator::RelinearizationKeys;
pub type GaloisKeys = key_generator::GaloisKeys;
pub type Evaluator = evaluator::Evaluator;
pub type Encryptor = encryptor::Encryptor;
pub type Decryptor = decryptor::Decryptor;
pub type Context = context::Context;
pub type BatchEncoder = batch_encoder::BatchEncoder;
pub type CKKSEncoder = ckks_encoder::CKKSEncoder;
pub const SCHEME_BFV: u8 = params::SCHEME_BFV;
pub const SCHEME_CKKS: u8 = params::SCHEME_CKKS;

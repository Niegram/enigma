use std::num::NonZeroU32;
use aes_gcm::aead::Aead;

use aes_gcm::KeyInit;
use ring::{digest, pbkdf2};

const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
const PASSWORD_HASH_ITERATIONS: u32 = 300_000;

pub fn encrypt_password(password: &[u8], salt: &[u8], server_salt: &[u8]) -> [u8; 64] {
    let n_iter = NonZeroU32::new(PASSWORD_HASH_ITERATIONS).unwrap();
    let mut first_pbkdf2_hash = [0u8; CREDENTIAL_LEN];
    let mut second_pbkdf2_hash = [0u8; CREDENTIAL_LEN];

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        server_salt,
        password,
        &mut first_pbkdf2_hash,
    );

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        salt,
        &first_pbkdf2_hash,
        &mut second_pbkdf2_hash,
    );

    second_pbkdf2_hash
}

pub fn verify_password(previous_hash: &[u8], password: &[u8], salt: &[u8], server_salt: &[u8]) -> bool {
    let n_iter = NonZeroU32::new(PASSWORD_HASH_ITERATIONS).unwrap();
    let mut first_pbkdf2_hash = [0u8; CREDENTIAL_LEN];

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        server_salt,
        password,
        &mut first_pbkdf2_hash,
    );

    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        salt,
        &first_pbkdf2_hash,
        previous_hash,
    ) == Ok(())
}

pub fn encrypt_data(data: &[u8], encryption_key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let key = aes_gcm::Aes256Gcm::new_from_slice(encryption_key).unwrap();

    let nonce = aes_gcm::Nonce::from_slice(nonce);

    key.encrypt(nonce, data).unwrap()
}

pub fn decrypt_data(data: &[u8], encryption_key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let key = aes_gcm::Aes256Gcm::new_from_slice(encryption_key).unwrap();
    let nonce = aes_gcm::Nonce::from_slice(nonce);

    key.decrypt(nonce, data).unwrap()
}
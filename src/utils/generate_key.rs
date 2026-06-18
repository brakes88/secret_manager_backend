use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngExt;
use rand_core::{OsRng, RngCore};

use crate::models::EncryptionMethod;

pub fn generate_key(method: &EncryptionMethod) -> Vec<u8> {
    let mut rng = OsRng;

    match method {
        EncryptionMethod::AES256 => {
            let mut key = vec![0u8; 32];
            rng.fill_bytes(&mut key[..]);
            key
        }
        EncryptionMethod::Chacha20 => {
            let mut key = vec![0u8; 32];
            rng.fill_bytes(&mut key[..]);
            key
        }
        EncryptionMethod::Blowfish => {
            let mut key = vec![0u8; 32];
            rng.fill_bytes(&mut key[..]);
            key
        }
        EncryptionMethod::DESTripleDES => {
            let mut key = vec![0u8; 21];
            rng.fill_bytes(&mut key[..]);
            key
        }
    }
}

pub fn generate_api_key() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis();

    let random_string: String = rand::rng()
        .sample_iter(&rand::distr::Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();

    format!("{}{}", timestamp, random_string)
}

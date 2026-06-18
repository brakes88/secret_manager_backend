use aes::{
    Aes256,
    cipher::{BlockModeEncrypt, KeyInit, StreamCipher},
};
use block_padding::Pkcs7;
use blowfish::Blowfish;
use chacha20::{ChaCha20, KeyIvInit};
use des::TdesEde3;

use crate::models::EncryptionMethod::{self, Chacha20};

const NONCE: [u8; 12] = [0; 12];

pub fn encrypt(method: &EncryptionMethod, key: &[u8], data: &[u8]) -> Vec<u8> {
    match method {
        EncryptionMethod::AES256 => {
            let key: [u8; 32] = key.try_into().expect("Key length must be 32 bytes");

            type Aes256EcbEnc = ecb::Encryptor<Aes256>;

            Aes256EcbEnc::new(&key.into()).encrypt_padded_vec::<Pkcs7>(data)
        }
        EncryptionMethod::Chacha20 => {
            let key: [u8; 32] = key.try_into().expect("Key length must be 32 bytes");

            let mut cipher = ChaCha20::new(&key.into(), &NONCE.into());

            let mut cipher_text = data.to_vec();

            cipher.apply_keystream(&mut cipher_text);

            cipher_text
        }
        EncryptionMethod::Blowfish => {
            let mut blowfish_key = [0u8; 32];
            let key_len = key.len().min(32);

            blowfish_key[..key_len].copy_from_slice(&key[..key_len]);

            type BlowfishEcbEnc = ecb::Encryptor<Blowfish>;

            BlowfishEcbEnc::new_from_slice(&blowfish_key)
                .expect("Blowfish encrypting error")
                .encrypt_padded_vec::<Pkcs7>(data)
        }
        EncryptionMethod::DESTripleDES => {
            let mut des_key = [0u8; 24];
            let key_len = key.len().min(24);
            des_key[..key_len].copy_from_slice(&key[..key_len]);

            type TdesEde3EcbEnc = ecb::Encryptor<TdesEde3>;

            TdesEde3EcbEnc::new_from_slice(&des_key)
                .expect("DESTripleDES encrypting error")
                .encrypt_padded_vec::<Pkcs7>(data)
        }
    }
}

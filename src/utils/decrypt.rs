use aes::{
    Aes256,
    cipher::{BlockModeDecrypt, KeyInit, StreamCipher},
};
use block_padding::Pkcs7;
use blowfish::Blowfish;
use chacha20::{ChaCha20, KeyIvInit};
use des::TdesEde3;

use crate::models::EncryptionMethod::{self};

const NONCE: [u8; 12] = [0; 12];

pub fn decrypt(method: &EncryptionMethod, key: &[u8], data: &[u8]) -> Vec<u8> {
    match method {
        EncryptionMethod::AES256 => {
            let key: [u8; 32] = key.try_into().expect("Key length must be 32 bytes");

            type Aes256EcbDec = ecb::Decryptor<Aes256>;

            Aes256EcbDec::new_from_slice(&key)
                .expect("AES256 generating decryptor from key gone wrong")
                .decrypt_padded_vec::<Pkcs7>(data)
                .expect("AES256 decrypting error")
        }
        EncryptionMethod::Chacha20 => {
            let key: [u8; 32] = key.try_into().expect("Key length must be 32 bytes");

            let mut cipher = ChaCha20::new(&key.into(), &NONCE.into());

            let mut decrypted_data = data.to_vec();

            cipher.apply_keystream(&mut decrypted_data);

            decrypted_data
        }
        EncryptionMethod::Blowfish => {
            let mut blowfish_key = [0u8; 32];
            let key_len = key.len().min(32);

            blowfish_key[..key_len].copy_from_slice(&key[..key_len]);

            type BlowfishEcbDec = ecb::Decryptor<Blowfish>;

            BlowfishEcbDec::new_from_slice(&blowfish_key)
                .expect("Blowfish generating decryptor from key gone wrong")
                .decrypt_padded_vec::<Pkcs7>(data)
                .expect("Blowfish decrypting error")
        }
        EncryptionMethod::DESTripleDES => {
            let mut des_key = [0u8; 24];
            let key_len = key.len().min(24);
            des_key[..key_len].copy_from_slice(&key[..key_len]);

            type TdesEde3EcbDec = ecb::Decryptor<TdesEde3>;

            TdesEde3EcbDec::new_from_slice(&des_key)
                .expect("DESTripleDES generating decryptor from key gone wrong")
                .decrypt_padded_vec::<Pkcs7>(data)
                .expect("DESTripleDES decrypting error")
        }
    }
}

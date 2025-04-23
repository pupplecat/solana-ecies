use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};
use solana_sdk::{pubkey::Pubkey, signer::keypair::Keypair};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

const NONCE_SIZE: usize = 12;
const CHALLENGE_SIZE: usize = 32;
const CIPHERTEXT_SIZE: usize = CHALLENGE_SIZE + 16;
const ECIES_OUTPUT_SIZE: usize = 32 + NONCE_SIZE + CIPHERTEXT_SIZE;

#[derive(Debug)]
pub enum EciesError {
    InvalidPublicKey,
    InvalidSecretKey,
    EncryptionFailed,
    DecryptionFailed(String),
}

impl std::fmt::Display for EciesError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EciesError::InvalidPublicKey => write!(f, "Invalid public key"),
            EciesError::InvalidSecretKey => write!(f, "Invalid secret key"),
            EciesError::EncryptionFailed => write!(f, "Encryption failed"),
            EciesError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
        }
    }
}

impl std::error::Error for EciesError {}

/// Converts an Ed25519 public key to an X25519 public key (MontgomeryPoint).
fn ed25519_to_curve25519_pubkey(pubkey: &Pubkey) -> Result<MontgomeryPoint, EciesError> {
    let ed25519_pubkey =
        VerifyingKey::from_bytes(&pubkey.to_bytes()).map_err(|_| EciesError::InvalidPublicKey)?;
    let x25519_bytes = ed25519_pubkey.to_montgomery().to_bytes();
    Ok(MontgomeryPoint(x25519_bytes))
}

/// Converts an Ed25519 secret key to an X25519 secret key.
fn ed25519_to_curve25519_secret(keypair: &Keypair) -> Result<X25519StaticSecret, EciesError> {
    let secret_bytes = keypair.secret().to_bytes();
    let ed25519_signing_key = SigningKey::from_bytes(&secret_bytes);

    // Use the secret key portion (first 32 bytes) and convert to X25519
    let mut hasher = Sha512::new();
    hasher.update(&ed25519_signing_key.to_bytes());
    let hash = hasher.finalize();
    let mut x25519_secret = [0u8; 32];
    x25519_secret.copy_from_slice(&hash[..32]);

    // Clamp for X25519
    x25519_secret[0] &= 248;
    x25519_secret[31] &= 127;
    x25519_secret[31] |= 64;

    Ok(X25519StaticSecret::from(x25519_secret))
}

/// Encrypts a challenge using ECIES with X25519.
pub fn ecies_encrypt(
    recipient_pubkey: &Pubkey,
    challenge: &[u8; CHALLENGE_SIZE],
) -> Result<[u8; ECIES_OUTPUT_SIZE], EciesError> {
    let recipient_point = ed25519_to_curve25519_pubkey(recipient_pubkey)?;
    let recipient_x25519 = X25519PublicKey::from(recipient_point.0);

    let ephemeral_secret = X25519StaticSecret::random_from_rng(OsRng);
    let ephemeral_pubkey = X25519PublicKey::from(&ephemeral_secret);

    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_x25519);

    // Validate shared secret
    if shared_secret.as_bytes() == &[0u8; 32] {
        return Err(EciesError::EncryptionFailed);
    }

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut sym_key = [0u8; 32];
    hkdf.expand(b"ecies-encryption", &mut sym_key)
        .map_err(|_| EciesError::EncryptionFailed)?;

    let cipher = Aes256Gcm::new_from_slice(&sym_key).map_err(|_| EciesError::EncryptionFailed)?;
    let random_seed = rand::rng().random::<[u8; NONCE_SIZE]>();
    let nonce = Nonce::from_slice(&random_seed);

    let ciphertext = cipher
        .encrypt(nonce, challenge.as_ref())
        .map_err(|_| EciesError::EncryptionFailed)?;

    if ciphertext.len() != CIPHERTEXT_SIZE {
        return Err(EciesError::EncryptionFailed);
    }

    let mut output = [0u8; ECIES_OUTPUT_SIZE];
    output[0..32].copy_from_slice(ephemeral_pubkey.as_bytes());
    output[32..32 + NONCE_SIZE].copy_from_slice(&random_seed);
    output[32 + NONCE_SIZE..].copy_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypts an ECIES ciphertext using the recipient's secret key.
pub fn ecies_decrypt(
    recipient_keypair: &Keypair,
    ciphertext: &[u8; ECIES_OUTPUT_SIZE],
) -> Result<[u8; CHALLENGE_SIZE], EciesError> {
    let ephemeral_pubkey = &ciphertext[0..32];
    let nonce = &ciphertext[32..32 + NONCE_SIZE];
    let encrypted_data = &ciphertext[32 + NONCE_SIZE..];

    println!("Decrypt ephemeral_pubkey len: {}", ephemeral_pubkey.len());
    println!("Decrypt nonce len: {}", nonce.len());
    println!("Decrypt encrypted_data len: {}", encrypted_data.len());

    let recipient_secret = ed25519_to_curve25519_secret(recipient_keypair)?;

    let ephemeral_bytes: [u8; 32] = ephemeral_pubkey
        .try_into()
        .map_err(|_| EciesError::InvalidPublicKey)?;
    let ephemeral_x25519 = X25519PublicKey::from(ephemeral_bytes);

    let shared_secret = recipient_secret.diffie_hellman(&ephemeral_x25519);

    if shared_secret.as_bytes() == &[0u8; 32] {
        return Err(EciesError::DecryptionFailed(
            "Invalid shared secret".to_string(),
        ));
    }

    println!("Decrypt shared secret: {:?}", shared_secret.as_bytes());

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut sym_key = [0u8; 32];
    hkdf.expand(b"ecies-encryption", &mut sym_key)
        .map_err(|_| EciesError::DecryptionFailed("HKDF expansion failed".to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(&sym_key)
        .map_err(|_| EciesError::DecryptionFailed("Invalid symmetric key".to_string()))?;
    let nonce = Nonce::from_slice(nonce);

    println!("Decrypt nonce: {:?}", nonce.as_slice());
    println!("Decrypt encrypted_data: {:?}", encrypted_data);

    let plaintext = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|e| EciesError::DecryptionFailed(format!("AES-GCM decryption error: {:?}", e)))?;

    let mut challenge = [0u8; CHALLENGE_SIZE];
    if plaintext.len() != CHALLENGE_SIZE {
        return Err(EciesError::DecryptionFailed(format!(
            "Invalid plaintext length: {}, expected: {}",
            plaintext.len(),
            CHALLENGE_SIZE
        )));
    }
    challenge.copy_from_slice(&plaintext);

    Ok(challenge)
}

/// Test the implementation
#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use solana_sdk::{signature::Signer, signer::keypair::Keypair};

    #[test]
    fn test_ecies_encrypt_decrypt() {
        let recipient_keypair = Keypair::new();
        let recipient_pubkey = recipient_keypair.pubkey();

        let challenge: [u8; 32] = rand::rng().random();
        let ciphertext = ecies_encrypt(&recipient_pubkey, &challenge).expect("Encryption failed");
        let decrypted = ecies_decrypt(&recipient_keypair, &ciphertext).expect("Decryption failed");
        assert_eq!(challenge, decrypted);
    }
}

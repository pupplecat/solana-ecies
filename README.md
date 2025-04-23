# solana-ecies

`solana-ecies` is a Rust library implementing the Elliptic Curve Integrated Encryption Scheme (ECIES) for Solana keypairs. It uses X25519 for key exchange, AES-256-GCM for encryption, and HKDF for key derivation. The library is designed to securely encrypt and decrypt data, such as challenges in Solana-based escrow systems, using Solana's Ed25519 keypairs converted to X25519.

This library is ideal for Solana developers building secure applications, such as escrow-based program, where sensitive data needs to be encrypted off-chain and decrypted by authorized parties.

## Features

- Secure Encryption: Encrypts 32-byte challenges using ECIES with X25519, AES-256-GCM, and HKDF.
- Solana Integration: Converts Solana Ed25519 keypairs (`Pubkey` and `Keypair`) to X25519 for seamless use.
- Robust Error Handling: Provides detailed error messages for debugging encryption/decryption failures.
- Tested and Reliable: Includes unit tests and debug logging for shared secrets and input validation.

## Installation

Add `solana-ecies` to your `Cargo.toml`:

```toml
[dependencies]
solana-ecies = "0.1.0"
```

## Usage

The library provides two main functions:

- `ecies_encrypt`: Encrypts a 32-byte challenge under a recipient’s Solana public key (Pubkey).
- `ecies_decrypt`: Decrypts the ciphertext using the recipient’s Solana keypair (Keypair).

## Example: Encrypting and Decrypting a Challenge

```rust
use solana_ecies::{ecies_encrypt, ecies_decrypt};
use solana_sdk::{pubkey::Pubkey, signer::keypair::Keypair};
use rand::RngCore;

fn main() {
    // Generate a recipient keypair
    let recipient_keypair = Keypair::new();
    let recipient_pubkey = recipient_keypair.pubkey();

    // Generate a random 32-byte challenge
    let challenge: [u8; 32] = rand::rng().random();

    // Encrypt the challenge
    let encrypted_challenge = ecies_encrypt(&recipient_pubkey, &challenge)
        .expect("Encryption failed");

    // Decrypt the challenge
    let decrypted_challenge = ecies_decrypt(&recipient_keypair, &encrypted_challenge)
        .expect("Decryption failed");

    // Verify the result
    assert_eq!(challenge, decrypted_challenge);
    println!("Successfully encrypted and decrypted challenge!");
}
```

### Security Considerations

- **Key Conversion**: Converts Solana Ed25519 keypairs to X25519 using `ed25519-dalek`’s `to_montgomery` for public keys and SHA-512 hashing with clamping for secret keys, following RFC 7748.
- **Cryptographic Primitives**: Uses X25519 for ECDH, AES-256-GCM for encryption, and HKDF-SHA256 for key derivation, ensuring strong security.
- **Nonce Safety**: Generates unique 12-byte nonces with `rand::rng().random()` to prevent reuse.
- **Validation**: Checks shared secrets and ciphertext lengths to prevent invalid operations.
- **Recommendations**:
  - Use a secure random number generator (e.g., `rand` or `OsRng`).
  - Protect `Keypair` secret keys in a secure environment.
  - Verify `challenge_hash` in escrow applications to prevent unauthorized claims.

## Testing

Run unit tests to verify encryption and decryption:

```bash
cargo test
```

The library includes tests for:

- Encrypting and decrypting challenges with valid Solana keypairs.
- Handling invalid keys and ciphertexts.
- Ensuring consistent shared secrets in ECDH.

## Dependencies

- **solana-sdk**: For Solana `Pubkey` and `Keypair` types.
- **curve25519-dalek**: For MontgomeryPoint in X25519 operations.
- **ed25519-dalek**: For Ed25519 key conversion.
- **x25519-dalek**: For X25519 ECDH.
- **aes-gcm**: For AES-256-GCM encryption.
- **hkdf and sha2**: For key derivation and hashing.
- **rand**: For random number generation.

## Contributing

Contributions are welcome! Please submit issues or pull requests to the GitHub repository. Ensure tests pass and follow Rust coding conventions.

## License

This project is licensed under the MIT License (LICENSE)

## Acknowledgments

Built for Solana developers creating secure escrow-based applications. Inspired by cryptographic best practices and the Solana ecosystem.

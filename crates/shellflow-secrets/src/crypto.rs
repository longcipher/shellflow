//! File encryption and decryption.
//!
//! Note: the age format is *anonymous* — the header stores the ephemeral
//! share, not the recipients — so recipients cannot be recovered from an
//! encrypted file. Re-encryption (`secret edit`) therefore takes the
//! recipients explicitly (`-r age1…` and/or `--recipients-dir`).

use std::io;

use zeroize::{Zeroize, Zeroizing};

use crate::error::SecretsError;

/// Encrypt `plain` to every recipient, returning the age file bytes.
///
/// # Errors
///
/// Returns [`SecretsError::MissingRecipients`] when `recipients` is empty and
/// [`SecretsError::Encrypt`] when encryption fails.
pub fn encrypt_bytes(
    plain: &[u8],
    recipients: &[age::x25519::Recipient],
) -> Result<Vec<u8>, SecretsError> {
    if recipients.is_empty() {
        return Err(SecretsError::MissingRecipients);
    }
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|err| SecretsError::Encrypt(err.to_string()))?;

    let mut out = Vec::with_capacity(plain.len() + 256);
    let mut writer =
        encryptor.wrap_output(&mut out).map_err(|err| SecretsError::Encrypt(err.to_string()))?;
    io::copy(&mut &plain[..], &mut writer).map_err(|err| SecretsError::Encrypt(err.to_string()))?;
    writer.finish().map_err(|err| SecretsError::Encrypt(err.to_string()))?;
    Ok(out)
}

/// Decrypt an age file with `identity`, returning the plaintext.
///
/// The plaintext is returned in a [`Zeroizing`] buffer: it is scrubbed when
/// the buffer is dropped, so the decrypted bytes do not linger in the heap
/// (and on their way to swap) for the rest of the process lifetime.
///
/// # Errors
///
/// Returns [`SecretsError::Decrypt`] when the file is not valid age data or
/// the identity cannot open it.
pub fn decrypt_bytes(
    cipher: &[u8],
    identity: &age::x25519::Identity,
) -> Result<Zeroizing<Vec<u8>>, SecretsError> {
    let decryptor =
        age::Decryptor::new(cipher).map_err(|err| SecretsError::Decrypt(err.to_string()))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|err| SecretsError::Decrypt(err.to_string()))?;

    let mut plain = Zeroizing::new(Vec::with_capacity(cipher.len()));
    io::copy(&mut reader, &mut *plain).map_err(|err| SecretsError::Decrypt(err.to_string()))?;
    Ok(plain)
}

/// Decrypt an age file with `identity`, returning the plaintext as text.
///
/// The plaintext is returned in a [`Zeroizing`] string: it is scrubbed when
/// the string is dropped, so the decrypted bytes do not linger in the heap
/// (and on their way to swap) for the rest of the process lifetime.
///
/// # Errors
///
/// Returns [`SecretsError::Decrypt`] when the file is not valid age data, the
/// identity cannot open it, or the plaintext is not valid UTF-8.
pub fn decrypt_string(
    cipher: &[u8],
    identity: &age::x25519::Identity,
) -> Result<Zeroizing<String>, SecretsError> {
    let mut bytes = decrypt_bytes(cipher, identity)?;
    // Move the buffer out of the `Zeroizing` wrapper (leaving it empty) so
    // the string owns it, then wrap the string instead: the plaintext is
    // still scrubbed exactly once, on drop.
    let text = String::from_utf8(std::mem::take(&mut *bytes)).map_err(|err| {
        // The error owns the plaintext buffer. Scrub it here, because
        // dropping it would leave the decrypted bytes in the heap unzeroed.
        let mut bytes = err.into_bytes();
        bytes.zeroize();
        drop(bytes);
        SecretsError::Decrypt("plaintext is not valid UTF-8".to_string())
    })?;
    Ok(Zeroizing::new(text))
}

#[cfg(test)]
mod tests {
    use age::secrecy::ExposeSecret;

    use super::*;

    fn make_identity() -> age::x25519::Identity {
        age::x25519::Identity::generate()
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let identity = make_identity();
        let recipient = identity.to_public();
        let plain = b"KEY=value\nSECRET=xyz\n";
        let cipher = encrypt_bytes(plain, &[recipient]).expect("encrypt");
        let round = decrypt_bytes(&cipher, &identity).expect("decrypt");
        assert_eq!(&*round, plain);
    }

    #[test]
    fn decrypt_string_returns_the_plaintext() {
        let identity = make_identity();
        let recipient = identity.to_public();
        let plain = "KEY=value\nSECRET=xyz\n";
        let cipher = encrypt_bytes(plain.as_bytes(), &[recipient]).expect("encrypt");
        let round = decrypt_string(&cipher, &identity).expect("decrypt");
        assert_eq!(&*round, plain);
    }

    #[test]
    fn decrypt_string_rejects_plaintext_that_is_not_utf8() {
        let identity = make_identity();
        let recipient = identity.to_public();
        let cipher = encrypt_bytes(&[0xff, 0xfe], &[recipient]).expect("encrypt");
        let err = decrypt_string(&cipher, &identity).expect_err("non-UTF8 plaintext must fail");
        assert!(err.to_string().contains("UTF-8"), "unexpected error: {err}");
    }

    #[test]
    fn encrypt_to_multiple_recipients_decrypts_with_each() {
        let a = make_identity();
        let b = make_identity();
        let plain = b"hello";
        let cipher = encrypt_bytes(plain, &[a.to_public(), b.to_public()]).expect("encrypt");
        assert_eq!(&*decrypt_bytes(&cipher, &a).expect("a"), plain);
        assert_eq!(&*decrypt_bytes(&cipher, &b).expect("b"), plain);
    }

    #[test]
    fn encrypt_without_recipients_fails() {
        let err = encrypt_bytes(b"x", &[]).expect_err("no recipients");
        assert!(matches!(err, SecretsError::MissingRecipients));
    }

    #[test]
    fn decrypt_with_wrong_identity_fails() {
        let identity = make_identity();
        let cipher = encrypt_bytes(b"secret", &[identity.to_public()]).expect("encrypt");
        let wrong = make_identity();
        assert!(matches!(decrypt_bytes(&cipher, &wrong), Err(SecretsError::Decrypt(_))));
    }

    #[test]
    fn garbage_input_is_rejected() {
        let identity = make_identity();
        assert!(matches!(decrypt_bytes(b"garbage", &identity), Err(SecretsError::Decrypt(_))));
    }

    #[test]
    fn identity_string_forms_are_standard() {
        let identity = make_identity();
        let encoded = identity.to_string();
        let s = encoded.expose_secret();
        assert!(s.starts_with("AGE-SECRET-KEY-1"), "got {s}");
        let pubkey = identity.to_public().to_string();
        assert!(pubkey.starts_with("age1"), "got {pubkey}");
    }
}

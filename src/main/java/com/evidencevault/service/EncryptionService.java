package com.evidencevault.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * All evidence files are encrypted at rest with AES-256 in GCM mode.
 * GCM gives us both confidentiality AND integrity (authentication tag) -
 * if a single byte of ciphertext is altered on disk, decryption fails loudly
 * instead of silently returning corrupted data. That's important for evidence.
 *
 * The master key comes from an environment variable so it is never checked
 * into source control. Each file additionally gets its own random 12-byte IV.
 */
@Service
public class EncryptionService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int IV_LENGTH_BYTES = 12;

    private final SecretKey masterKey;
    private final java.util.List<SecretKey> previousMasterKeys;
    private final SecureRandom secureRandom = new SecureRandom();

    public EncryptionService(@Value("${evidencevault.encryption.master-key-base64}") String masterKeyBase64,
                              @Value("${evidencevault.encryption.previous-master-keys-base64:}") String previousMasterKeysCsv) {
        byte[] keyBytes = Base64.getDecoder().decode(masterKeyBase64);
        if (keyBytes.length != 32) {
            throw new IllegalStateException(
                "evidencevault.encryption.master-key-base64 must decode to exactly 32 bytes (AES-256). " +
                "Generate one with: openssl rand -base64 32");
        }
        this.masterKey = new SecretKeySpec(keyBytes, "AES");

        // Retired master keys, kept around only so cases whose DEK hasn't been rotated onto the
        // new master key yet can still be unwrapped. See rotateCaseKey() in CaseService: once a
        // case's DEK is re-wrapped under the current master key, it no longer needs these.
        this.previousMasterKeys = new java.util.ArrayList<>();
        if (previousMasterKeysCsv != null && !previousMasterKeysCsv.isBlank()) {
            for (String encoded : previousMasterKeysCsv.split(",")) {
                if (encoded.isBlank()) continue;
                byte[] prevBytes = Base64.getDecoder().decode(encoded.trim());
                if (prevBytes.length != 32) {
                    throw new IllegalStateException(
                        "Each key in evidencevault.encryption.previous-master-keys-base64 must decode to 32 bytes");
                }
                this.previousMasterKeys.add(new SecretKeySpec(prevBytes, "AES"));
            }
        }
    }

    public byte[] generateIv() {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /** Encrypts using the server-wide master key. Used only to wrap/unwrap per-case DEKs now -
     *  see the envelope-encryption methods below for actual evidence file content. */
    public byte[] encrypt(byte[] plaintext, byte[] iv) {
        return encryptWithKey(plaintext, iv, masterKey);
    }

    public byte[] decrypt(byte[] ciphertext, byte[] iv) {
        return decryptWithKey(ciphertext, iv, masterKey);
    }

    public byte[] encryptWithKey(byte[] plaintext, byte[] iv, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    public byte[] decryptWithKey(byte[] ciphertext, byte[] iv, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            // Covers auth tag mismatch -> tampering/corruption of ciphertext on disk
            throw new IllegalStateException("Decryption failed - ciphertext may be corrupted or tampered with", e);
        }
    }

    // ---- Envelope encryption: per-case data encryption keys (DEKs) wrapped by the master key ----

    /** Generates a fresh random AES-256 key for a single case. Never leaves this service in the clear. */
    public SecretKey generateDataKey() {
        byte[] keyBytes = new byte[32];
        secureRandom.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    public record WrappedKey(String wrappedKeyBase64, String ivBase64) {}

    /** Encrypts (wraps) a case's DEK with the master key, so only the wrapped form is persisted. */
    public WrappedKey wrapKey(SecretKey dek) {
        byte[] iv = generateIv();
        byte[] wrapped = encrypt(dek.getEncoded(), iv);
        return new WrappedKey(Base64.getEncoder().encodeToString(wrapped), Base64.getEncoder().encodeToString(iv));
    }

    /** Reverses wrapKey(): decrypts the stored wrapped DEK back into a usable AES key. Tries the
     *  current master key first; if that fails (e.g. this DEK was wrapped before a key rotation),
     *  falls back through the retired keys in previousMasterKeys before giving up. */
    public SecretKey unwrapKey(String wrappedKeyBase64, String ivBase64) {
        byte[] iv = Base64.getDecoder().decode(ivBase64);
        byte[] wrapped = Base64.getDecoder().decode(wrappedKeyBase64);
        try {
            byte[] rawKey = decryptWithKey(wrapped, iv, masterKey);
            return new SecretKeySpec(rawKey, "AES");
        } catch (Exception currentKeyFailure) {
            for (SecretKey oldKey : previousMasterKeys) {
                try {
                    byte[] rawKey = decryptWithKey(wrapped, iv, oldKey);
                    return new SecretKeySpec(rawKey, "AES");
                } catch (Exception ignored) {
                    // try the next retired key
                }
            }
            throw currentKeyFailure instanceof IllegalStateException ise ? ise
                    : new IllegalStateException("Decryption failed - ciphertext may be corrupted or tampered with", currentKeyFailure);
        }
    }
        /** Encrypts arbitrary text at rest under the master key - for secrets that need to be
     *  recovered in full (e.g. a user's RSA private key) as opposed to wrapKey/unwrapKey, which
     *  is specifically for AES DEKs. IV is stored alongside the ciphertext in one Base64 string
     *  so callers only need to persist a single column. */
    public String encryptStringWithMasterKey(String plaintext) {
        byte[] iv = generateIv();
        byte[] ciphertext = encrypt(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8), iv);
        java.nio.ByteBuffer buffer = java.nio.ByteBuffer.allocate(iv.length + ciphertext.length);
        buffer.put(iv).put(ciphertext);
        return Base64.getEncoder().encodeToString(buffer.array());
    }

    /** Reverses encryptStringWithMasterKey(). Tries the current master key first, then falls back
     *  through retired keys, same rotation-safety as unwrapKey(). */
    public String decryptStringWithMasterKey(String storedBase64) {
        byte[] combined = Base64.getDecoder().decode(storedBase64);
        byte[] iv = java.util.Arrays.copyOfRange(combined, 0, IV_LENGTH_BYTES);
        byte[] ciphertext = java.util.Arrays.copyOfRange(combined, IV_LENGTH_BYTES, combined.length);
        try {
            byte[] plaintext = decryptWithKey(ciphertext, iv, masterKey);
            return new String(plaintext, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception currentKeyFailure) {
            for (SecretKey oldKey : previousMasterKeys) {
                try {
                    byte[] plaintext = decryptWithKey(ciphertext, iv, oldKey);
                    return new String(plaintext, java.nio.charset.StandardCharsets.UTF_8);
                } catch (Exception ignored) {
                    // try the next retired key
                }
            }
            throw currentKeyFailure instanceof IllegalStateException ise ? ise
                    : new IllegalStateException("Decryption failed - ciphertext may be corrupted or tampered with", currentKeyFailure);
        }
    }

    /** True once a case's DEK has already been re-wrapped under the current master key - i.e.
     *  unwrapping it succeeds without needing to fall back to any retired key. Used to report
     *  rotation status without performing a rotation. */
    public boolean isWrappedWithCurrentKey(String wrappedKeyBase64, String ivBase64) {
        byte[] iv = Base64.getDecoder().decode(ivBase64);
        byte[] wrapped = Base64.getDecoder().decode(wrappedKeyBase64);
        try {
            decryptWithKey(wrapped, iv, masterKey);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

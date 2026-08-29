package com.evidencevault.service;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Minimal RFC 6238 TOTP (the algorithm behind Google Authenticator / Authy) implemented directly
 * with javax.crypto, so no extra dependency is needed. Used to require a second factor for ADMIN
 * accounts, since ADMIN is the only role that can view/verify the tamper-evident audit chain.
 *
 * Standard parameters: HMAC-SHA1, 6 digits, 30-second step. A +/-1 step window is allowed on
 * verification to tolerate minor clock drift between server and authenticator app.
 */
@Service
public class TotpService {

    private static final int TIME_STEP_SECONDS = 30;
    private static final int CODE_DIGITS = 6;
    private static final int ALLOWED_STEP_DRIFT = 1;

    private final SecureRandom secureRandom = new SecureRandom();

    /** Generates a random 20-byte (160-bit) secret, Base32-encoded for authenticator app entry. */
    public String generateSecretBase32() {
        byte[] raw = new byte[20];
        secureRandom.nextBytes(raw);
        return base32Encode(raw);
    }

    /** Builds the otpauth:// URI an authenticator app can render as a QR code. */
    public String buildOtpAuthUri(String secretBase32, String username) {
        String issuer = "EvidenceVault";
        return "otpauth://totp/" + issuer + ":" + username
                + "?secret=" + secretBase32
                + "&issuer=" + issuer
                + "&digits=" + CODE_DIGITS
                + "&period=" + TIME_STEP_SECONDS;
    }

    /** Verifies a 6-digit code against the secret, allowing +/-1 time step of drift. */
    public boolean verifyCode(String secretBase32, String code) {
        if (code == null || !code.matches("\\d{6}")) return false;
        long currentStep = Instant.now().getEpochSecond() / TIME_STEP_SECONDS;
        byte[] key = base32Decode(secretBase32);
        for (int drift = -ALLOWED_STEP_DRIFT; drift <= ALLOWED_STEP_DRIFT; drift++) {
            String expected = generateCode(key, currentStep + drift);
            if (expected.equals(code)) return true;
        }
        return false;
    }

    private String generateCode(byte[] key, long step) {
        try {
            byte[] stepBytes = new byte[8];
            for (int i = 7; i >= 0; i--) {
                stepBytes[i] = (byte) (step & 0xFF);
                step >>= 8;
            }
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(stepBytes);

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);
            int code = binary % (int) Math.pow(10, CODE_DIGITS);
            return String.format("%0" + CODE_DIGITS + "d", code);
        } catch (Exception e) {
            throw new IllegalStateException("TOTP generation failed", e);
        }
    }

    /** Generates a set of human-typeable one-time backup codes, e.g. "7F3K-9QXR". Hashing and
     *  storage is the caller's responsibility (AuthService), same as it is for passwords. */
    public java.util.List<String> generateBackupCodes(int count) {
        java.util.List<String> codes = new java.util.ArrayList<>(count);
        String alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // no 0/O/1/I - avoids ambiguity
        for (int i = 0; i < count; i++) {
            StringBuilder sb = new StringBuilder();
            for (int block = 0; block < 2; block++) {
                if (block > 0) sb.append('-');
                for (int c = 0; c < 4; c++) {
                    sb.append(alphabet.charAt(secureRandom.nextInt(alphabet.length())));
                }
            }
            codes.add(sb.toString());
        }
        return codes;
    }

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int bits = 0, value = 0;
        for (byte b : data) {
            value = (value << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                sb.append(BASE32_ALPHABET.charAt((value >>> (bits - 5)) & 0x1F));
                bits -= 5;
            }
        }
        if (bits > 0) {
            sb.append(BASE32_ALPHABET.charAt((value << (5 - bits)) & 0x1F));
        }
        return sb.toString();
    }

    private byte[] base32Decode(String encoded) {
        String clean = encoded.trim().toUpperCase().replace("=", "");
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int bits = 0, value = 0;
        for (char c : clean.toCharArray()) {
            int idx = BASE32_ALPHABET.indexOf(c);
            if (idx < 0) continue;
            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8) {
                out.write((value >>> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }
}

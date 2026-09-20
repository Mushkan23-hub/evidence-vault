// AuditHasher.java - delimiter-safe, optionally keyed hashing for the audit chain.
//
// WHY: a hash built as SHA-256(seq + timestamp + actor + action + ... ) with plain string
// concatenation is ambiguous: fields ("ab","c") and ("a","bc") produce the same input.
// Length-prefixing every field removes that ambiguity. Using HMAC-SHA256 with a secret key
// also stops someone who can only write to the database from recomputing a valid chain.
//
// TRY IT (Java 21):   java docs/AuditHasher.java
// USE IT: move this class into src/main/java/<your package>/, add your package line,
// and call AuditHasher.entryHash(...) where you currently compute entryHash.
//
// IMPORTANT: changing the hash format invalidates existing rows. Either reset the demo database,
// or store a hashVersion column and verify old rows with the old formula and new rows with this one.

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class AuditHasher {
    private static final byte[] VERSION_TAG = "audit-v2".getBytes(StandardCharsets.UTF_8);

    private AuditHasher() {}

    /** Length-prefixed encoding: each field is 4-byte length + UTF-8 bytes; null is length -1. */
    static byte[] canonical(String... fields) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(ByteBuffer.allocate(4).putInt(VERSION_TAG.length).array());
        out.writeBytes(VERSION_TAG);
        for (String f : fields) {
            if (f == null) {
                out.writeBytes(ByteBuffer.allocate(4).putInt(-1).array());
            } else {
                byte[] b = f.getBytes(StandardCharsets.UTF_8);
                out.writeBytes(ByteBuffer.allocate(4).putInt(b.length).array());
                out.writeBytes(b);
            }
        }
        return out.toByteArray();
    }

    /**
     * @param hmacKey secret key (for example 32 bytes from an env var separate from the JWT key),
     *                or null for plain SHA-256.
     * @param fields  sequenceNumber, timestamp, actorUsername, action, caseId, evidenceId, details, previousHash
     */
    public static String entryHash(byte[] hmacKey, String... fields) {
        try {
            byte[] input = canonical(fields);
            byte[] digest;
            if (hmacKey == null) {
                digest = MessageDigest.getInstance("SHA-256").digest(input);
            } else {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
                digest = mac.doFinal(input);
            }
            return HexFormat.of().formatHex(digest);
        } catch (Exception e) {
            throw new IllegalStateException("hashing failed", e);
        }
    }

    /** Constant-time comparison for verifying stored hashes. */
    public static boolean matches(String expectedHex, String actualHex) {
        return MessageDigest.isEqual(
            expectedHex.getBytes(StandardCharsets.UTF_8), actualHex.getBytes(StandardCharsets.UTF_8));
    }

    // ---- demonstration / self-check ----
    public static void main(String[] args) {
        byte[] key = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

        // 1. Ambiguity that plain concatenation has, and this format does not
        String a = entryHash(null, "ab", "c");
        String b = entryHash(null, "a", "bc");
        check("field boundaries are unambiguous", !a.equals(b));

        // 2. Chain of two entries, then tamper with the first
        String h1 = entryHash(key, "1", "2026-09-19T10:00:00Z", "alice", "UPLOAD", "7", "9", "file=a.txt", "GENESIS");
        String h2 = entryHash(key, "2", "2026-09-19T10:05:00Z", "alice", "VERIFY", "7", "9", "ok", h1);
        String h1Tampered = entryHash(key, "1", "2026-09-19T10:00:00Z", "alice", "UPLOAD", "7", "9", "file=EVIL.txt", "GENESIS");
        check("recomputing an untouched entry matches", matches(h1, entryHash(key, "1", "2026-09-19T10:00:00Z", "alice", "UPLOAD", "7", "9", "file=a.txt", "GENESIS")));
        check("edited details change the hash", !matches(h1, h1Tampered));
        check("entry 2 no longer links to a tampered entry 1", !matches(h2, entryHash(key, "2", "2026-09-19T10:05:00Z", "alice", "VERIFY", "7", "9", "ok", h1Tampered)));

        // 3. Keyed vs unkeyed: an attacker without the key cannot forge a valid hash
        String forged = entryHash(null, "1", "2026-09-19T10:00:00Z", "alice", "UPLOAD", "7", "9", "file=EVIL.txt", "GENESIS");
        check("unkeyed forgery does not match the HMAC", !matches(h1, forged));

        // 4. null fields are handled and distinct from empty strings
        check("null differs from empty string", !entryHash(null, (String) null).equals(entryHash(null, "")));
        System.out.println("All AuditHasher checks passed.");
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "PASS  " : "FAIL  ") + name);
        if (!ok) throw new AssertionError(name);
    }
}

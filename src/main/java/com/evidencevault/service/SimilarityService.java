package com.evidencevault.service;

import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A simplified stand-in for real fuzzy-hashing algorithms like ssdeep. Real fuzzy hashing uses
 * content-defined (rolling-hash) chunk boundaries so insertions/deletions don't shift every
 * chunk; this implementation uses fixed-size chunks, which is easier to reason about and
 * implement correctly but is more sensitive to inserted/deleted bytes than a production fuzzy
 * hash would be. It's still useful for detecting files that share large identical regions.
 */
@Service
public class SimilarityService {

    private static final int CHUNK_SIZE = 64;

    public Set<String> fingerprint(byte[] data) {
        Set<String> chunks = new LinkedHashSet<>();
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (int offset = 0; offset < data.length; offset += CHUNK_SIZE) {
                int end = Math.min(offset + CHUNK_SIZE, data.length);
                byte[] chunk = new byte[end - offset];
                System.arraycopy(data, offset, chunk, 0, end - offset);
                byte[] hash = digest.digest(chunk);
                byte[] shortHash = new byte[4];
                System.arraycopy(hash, 0, shortHash, 0, 4);
                chunks.add(HexFormat.of().formatHex(shortHash));
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
        return chunks;
    }

    public String fingerprintToString(Set<String> fingerprint) {
        return String.join(",", fingerprint);
    }

    public Set<String> stringToFingerprint(String s) {
        if (s == null || s.isBlank()) return Set.of();
        return new LinkedHashSet<>(Set.of(s.split(",")));
    }

    /** Jaccard similarity of two chunk-hash sets, as a percentage. */
    public double similarityPercent(Set<String> a, Set<String> b) {
        if (a.isEmpty() && b.isEmpty()) return 100.0;
        Set<String> intersection = new LinkedHashSet<>(a);
        intersection.retainAll(b);
        Set<String> union = new LinkedHashSet<>(a);
        union.addAll(b);
        if (union.isEmpty()) return 0.0;
        return (intersection.size() * 100.0) / union.size();
    }
}

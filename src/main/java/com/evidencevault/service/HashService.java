package com.evidencevault.service;

import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

@Service
public class HashService {

    /** Returns lowercase hex-encoded SHA-256 digest of the given bytes. */
    public String sha256Hex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be present on every standard JVM
            throw new IllegalStateException("SHA-256 algorithm unavailable", e);
        }
    }

    public String sha256Hex(String text) {
        return sha256Hex(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}

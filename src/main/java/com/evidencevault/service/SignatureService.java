package com.evidencevault.service;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Every user gets an RSA-2048 key pair at registration. When they upload evidence, the SHA-256
 * hash of that file is signed with their private key. Anyone can later verify, using only the
 * user's public key, that this specific person's key produced this specific signature over this
 * specific hash - proof of WHO certified the evidence, independent of trusting the database.
 */
@Service
public class SignatureService {

    public KeyPairData generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            String publicKeyB64 = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
            String privateKeyB64 = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
            return new KeyPairData(publicKeyB64, privateKeyB64);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA algorithm unavailable", e);
        }
    }

    public String sign(String privateKeyBase64, String data) {
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyBase64));
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = factory.generatePrivate(spec);

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            throw new IllegalStateException("Signing failed", e);
        }
    }

    public boolean verify(String publicKeyBase64, String data, String signatureBase64) {
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyBase64));
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = factory.generatePublic(spec);

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            return signature.verify(Base64.getDecoder().decode(signatureBase64));
        } catch (Exception e) {
            return false;
        }
    }

    public record KeyPairData(String publicKeyBase64, String privateKeyBase64) {}
}

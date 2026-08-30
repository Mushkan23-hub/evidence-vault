package com.evidencevault.config;

import com.evidencevault.model.*;
import com.evidencevault.repository.CaseRepository;
import com.evidencevault.repository.EvidenceFileRepository;
import com.evidencevault.repository.UserRepository;
import com.evidencevault.service.EncryptionService;
import com.evidencevault.service.HashService;
import com.evidencevault.service.SignatureService;
import com.evidencevault.service.SimilarityService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;

/**
 * Seeds one demo case with one piece of evidence so a professor/reviewer/interviewer sees a
 * populated dashboard on first run instead of an empty one. Controlled by
 * evidencevault.seed-demo-data (default true) - set to false for a real deployment, since this
 * creates a real (if clearly-labeled) demo user with a known password.
 *
 * Only seeds if NO cases exist yet, so it never overwrites real data and only fires once.
 * Runs after AdminBootstrapSeeder (@Order(2)) since it needs a real user to attach the case to.
 */
@Component
@Order(2)
@RequiredArgsConstructor
public class DemoDataSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoDataSeeder.class);
    private static final String DEMO_USERNAME = "demo_investigator";
    private static final String DEMO_PASSWORD = "DemoPass123!"; // intentionally simple - seeded, not a real account

    private final CaseRepository caseRepository;
    private final UserRepository userRepository;
    private final EvidenceFileRepository evidenceFileRepository;
    private final PasswordEncoder passwordEncoder;
    private final SignatureService signatureService;
    private final EncryptionService encryptionService;
    private final HashService hashService;
    private final SimilarityService similarityService;

    @Value("${evidencevault.seed-demo-data:true}")
    private boolean seedEnabled;

    @Value("${evidencevault.storage.dir}")
    private String storageDir;

    @Override
    public void run(String... args) throws Exception {
        if (!seedEnabled || caseRepository.count() > 0) {
            return; // disabled, or real data already exists - never overwrite
        }

        User demoUser = userRepository.findByUsername(DEMO_USERNAME).orElseGet(() -> {
            var keyPair = signatureService.generateKeyPair();
            User u = User.builder()
                    .username(DEMO_USERNAME)
                    .email("demo@example.test")
                    .password(passwordEncoder.encode(DEMO_PASSWORD))
                    .role(Role.INVESTIGATOR)
                    .rsaPublicKey(keyPair.publicKeyBase64())
                    .rsaPrivateKey(encryptionService.encryptStringWithMasterKey(keyPair.privateKeyBase64()))
                    .build();
            return userRepository.save(u);
        });

        SecretKey dek = encryptionService.generateDataKey();
        EncryptionService.WrappedKey wrapped = encryptionService.wrapKey(dek);

        Case demoCase = Case.builder()
                .caseNumber("DEMO-2026-001")
                .title("Sample Case: Suspicious USB Drive")
                .description("Auto-seeded demo case for evaluation purposes. Contains one sample "
                        + "text artifact so the Evidence, Analysis, and Audit Chain views have "
                        + "something to show. Disable via evidencevault.seed-demo-data=false.")
                .createdBy(demoUser)
                .wrappedDekBase64(wrapped.wrappedKeyBase64())
                .dekWrapIvBase64(wrapped.ivBase64())
                .build();
        demoCase.getAssignedInvestigators().add(demoUser);
        caseRepository.save(demoCase);

        byte[] plaintext = ("EvidenceVault demo artifact.\n"
                + "This is a sample text file seeded automatically so you can immediately try:\n"
                + "- Verify Integrity\n- Detect File Type\n- Hex Dump\n- Extract Strings\n"
                + "- Digital Signature verification\n\nNothing sensitive here - it's just demo content.\n")
                .getBytes(StandardCharsets.UTF_8);

        String sha256 = hashService.sha256Hex(plaintext);
        byte[] iv = encryptionService.generateIv();
        byte[] ciphertext = encryptionService.encryptWithKey(plaintext, iv, dek);

        String storedFilename = java.util.UUID.randomUUID() + ".enc";
        var storagePath = java.nio.file.Path.of(storageDir);
        java.nio.file.Files.createDirectories(storagePath);
        java.nio.file.Files.write(storagePath.resolve(storedFilename), ciphertext);

        String privateKey = encryptionService.decryptStringWithMasterKey(demoUser.getRsaPrivateKey());
        String signature = signatureService.sign(privateKey, sha256);
        Set<String> fingerprint = similarityService.fingerprint(plaintext);

        EvidenceFile demoEvidence = EvidenceFile.builder()
                .evidenceCase(demoCase)
                .originalFilename("demo_artifact.txt")
                .storedFilename(storedFilename)
                .contentType("text/plain")
                .originalSizeBytes(plaintext.length)
                .sha256Hash(sha256)
                .encryptionIv(Base64.getEncoder().encodeToString(iv))
                .uploadedBy(demoUser)
                .signatureBase64(signature)
                .fingerprintData(similarityService.fingerprintToString(fingerprint))
                .build();
        evidenceFileRepository.save(demoEvidence);

        log.info("Seeded demo case '{}' with one evidence file, owned by user '{}' (password: {}). "
                        + "Set evidencevault.seed-demo-data=false to disable this in a real deployment.",
                demoCase.getCaseNumber(), DEMO_USERNAME, DEMO_PASSWORD);
    }
}

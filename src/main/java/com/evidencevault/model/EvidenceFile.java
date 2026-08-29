package com.evidencevault.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "evidence_files")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EvidenceFile {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "case_id")
    private Case evidenceCase;

    @Column(nullable = false)
    private String originalFilename;

    /** Random filename used on disk so the stored blob name leaks no info. */
    @Column(nullable = false, unique = true)
    private String storedFilename;

    @Column(nullable = false)
    private String contentType;

    @Column(nullable = false)
    private long originalSizeBytes;

    /** SHA-256 of the ORIGINAL plaintext content at upload time. This is the evidentiary fingerprint. */
    @Column(nullable = false, length = 64)
    private String sha256Hash;

    /** Base64-encoded AES-GCM initialization vector, unique per file. */
    @Column(nullable = false)
    private String encryptionIv;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "uploaded_by")
    private User uploadedBy;

    @Column(nullable = false, updatable = false)
    private Instant uploadedAt;

    private Instant lastVerifiedAt;

    private Boolean lastVerificationPassed;

    /** RSA signature (base64) of sha256Hash, signed with the uploader's private key at upload time. */
    @Column(columnDefinition = "TEXT")
    private String signatureBase64;

    /** Two-person integrity: a second investigator must witness the upload before full custody is established. */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private CustodyStatus custodyStatus = CustodyStatus.PENDING_WITNESS;

    private String witnessUsername;

    private Instant witnessedAt;

    /** Simplified similarity fingerprint - comma-separated chunk hashes, used for near-duplicate detection. */
    @Column(columnDefinition = "TEXT")
    private String fingerprintData;

    @PrePersist
    public void prePersist() {
        if (uploadedAt == null) {
            uploadedAt = Instant.now();
        }
    }
}

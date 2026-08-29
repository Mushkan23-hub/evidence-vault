package com.evidencevault.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Each entry stores the SHA-256 hash of the PREVIOUS entry plus its own content.
 * entryHash = SHA256(previousHash + timestamp + actor + action + details).
 * This means if anyone edits or deletes a past log row, every entry hash after it
 * stops matching what a fresh recompute produces - the tampering becomes detectable.
 * This is the same core idea used in blockchains and in real forensic logging tools.
 */
@Entity
@Table(name = "audit_log")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditLogEntry {

    @Id
    @GeneratedValue
    private UUID id;

    /** Monotonically increasing sequence number - makes chain order unambiguous. */
    @Column(nullable = false, unique = true)
    private long sequenceNumber;

    @Column(nullable = false)
    private Instant timestamp;

    @Column(nullable = false)
    private String actorUsername;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditAction action;

    private UUID relatedCaseId;

    private UUID relatedEvidenceId;

    @Column(length = 1000)
    private String details;

    @Column(nullable = false, length = 64)
    private String previousHash;

    @Column(nullable = false, length = 64, unique = true)
    private String entryHash;
}

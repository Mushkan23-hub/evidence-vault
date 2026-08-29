package com.evidencevault.dto;

import com.evidencevault.model.AuditAction;

import java.time.Instant;
import java.util.UUID;

public class AuditDtos {

    public record AuditEntryResponse(
            long sequenceNumber,
            Instant timestamp,
            String actorUsername,
            AuditAction action,
            UUID relatedCaseId,
            UUID relatedEvidenceId,
            String details,
            String previousHash,
            String entryHash
    ) {}

    public record ChainVerificationResponse(
            boolean intact,
            long lastValidSequence,
            String message
    ) {}
}

package com.evidencevault.dto;

import jakarta.validation.constraints.NotBlank;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public class EvidenceDtos {

    public record EvidenceResponse(
            UUID id,
            UUID caseId,
            String caseNumber,
            String originalFilename,
            String contentType,
            long originalSizeBytes,
            String sha256Hash,
            String uploadedBy,
            Instant uploadedAt,
            Instant lastVerifiedAt,
            Boolean lastVerificationPassed,
            String custodyStatus,
            String witnessUsername,
            Instant witnessedAt
    ) {}

    public record VerificationResponse(
            UUID evidenceId,
            boolean integrityPassed,
            String originalHash,
            String recomputedHash,
            String message
    ) {}

    public record AddNoteRequest(
            @NotBlank String content
    ) {}

    /**
     * Structured search filters, all optional and combinable. Query params map directly onto
     * this: q (filename/hash substring), caseId, uploadedBy (username), status (CustodyStatus),
     * uploadedAfter / uploadedBefore (ISO-8601 instants). Any filter left null/blank is skipped.
     */
    public record EvidenceSearchFilters(
            String q,
            UUID caseId,
            String uploadedBy,
            String custodyStatus,
            Instant uploadedAfter,
            Instant uploadedBefore
    ) {}

    public record NoteResponse(
            UUID id,
            String authorUsername,
            String content,
            Instant createdAt
    ) {}

    public record FileTypeResponse(
            String detectedType,
            String claimedContentType,
            String claimedExtension,
            boolean mismatch,
            String signatureHex
    ) {}

    public record HexDumpResponse(
            List<String> lines,
            int bytesShown,
            long totalFileSizeBytes
    ) {}

    public record StringsResponse(
            List<String> strings,
            int totalFound,
            boolean truncated
    ) {}

    public record SignatureResponse(
            String signerUsername,
            String publicKeyFingerprint,
            String signatureBase64,
            boolean verified
    ) {}

    public record SimilarEvidenceResponse(
            UUID evidenceId,
            String filename,
            String caseNumber,
            double similarityPercent
    ) {}
}

package com.evidencevault.service;

import com.evidencevault.dto.EvidenceDtos.*;
import com.evidencevault.model.AuditAction;
import com.evidencevault.model.Case;
import com.evidencevault.model.CustodyStatus;
import com.evidencevault.model.EvidenceFile;
import com.evidencevault.model.EvidenceNote;
import com.evidencevault.model.User;
import com.evidencevault.repository.EvidenceFileRepository;
import com.evidencevault.repository.EvidenceNoteRepository;
import com.evidencevault.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class EvidenceService {

    private final EvidenceFileRepository evidenceFileRepository;
    private final EvidenceNoteRepository evidenceNoteRepository;
    private final UserRepository userRepository;
    private final CaseService caseService;
    private final EncryptionService encryptionService;
    private final HashService hashService;
    private final AuditLogService auditLogService;
    private final ForensicAnalysisService forensicAnalysisService;
    private final SignatureService signatureService;
    private final SimilarityService similarityService;
    private final ClamAvScanService clamAvScanService;

    @Value("${evidencevault.storage.dir}")
    private String storageDir;

    @Value("${evidencevault.storage.max-user-quota-bytes:5368709120}") // default 5GB per user
    private long maxUserQuotaBytes;

    @Transactional
    public EvidenceResponse uploadEvidence(String username, UUID caseId, MultipartFile file) {
        try {
            Case evidenceCase = caseService.assertAccess(username, caseId);
            User uploader = userRepository.findByUsername(username)
                    .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));

            byte[] plaintext = file.getBytes();
            enforceQuota(uploader, plaintext.length);

            // Malware scan runs on the RAW plaintext before it's encrypted or stored anywhere.
            // If ClamAV isn't configured (evidencevault.clamav.enabled=false), this is a no-op
            // that always reports clean - see ClamAvScanService for the fail-closed behavior
            // when scanning IS enabled but the daemon can't be reached.
            ClamAvScanService.ScanResult scanResult = clamAvScanService.scan(plaintext);
            if (!scanResult.clean()) {
                auditLogService.record(username, AuditAction.EVIDENCE_UPLOAD_BLOCKED, caseId, null,
                        "Upload of '" + file.getOriginalFilename() + "' blocked by malware scan: " + scanResult.detail());
                throw new IllegalArgumentException("Upload rejected by malware scan: " + scanResult.detail());
            }

            String sha256 = hashService.sha256Hex(plaintext); // fingerprint of ORIGINAL content

            // Envelope encryption: unwrap this case's DEK just long enough to encrypt the file.
            SecretKey caseKey = caseService.getCaseDataKey(evidenceCase);
            byte[] iv = encryptionService.generateIv();
            byte[] ciphertext = encryptionService.encryptWithKey(plaintext, iv, caseKey);

            String storedFilename = UUID.randomUUID() + ".enc";
            Path storagePath = Path.of(storageDir);
            Files.createDirectories(storagePath);
            Files.write(storagePath.resolve(storedFilename), ciphertext);

            // Digital signature: uploader's private key signs the hash, proving WHO certified this file
            String signature = signatureService.sign(uploader.getRsaPrivateKey(), sha256);

            // Similarity fingerprint for near-duplicate detection
            Set<String> fingerprint = similarityService.fingerprint(plaintext);
            String fingerprintData = similarityService.fingerprintToString(fingerprint);

            EvidenceFile evidenceFile = EvidenceFile.builder()
                    .evidenceCase(evidenceCase)
                    .originalFilename(file.getOriginalFilename())
                    .storedFilename(storedFilename)
                    .contentType(file.getContentType() == null ? "application/octet-stream" : file.getContentType())
                    .originalSizeBytes(plaintext.length)
                    .sha256Hash(sha256)
                    .encryptionIv(Base64.getEncoder().encodeToString(iv))
                    .uploadedBy(uploader)
                    .signatureBase64(signature)
                    .fingerprintData(fingerprintData)
                    .build();
            evidenceFileRepository.save(evidenceFile);

            auditLogService.record(username, AuditAction.EVIDENCE_UPLOADED, caseId, evidenceFile.getId(),
                    "Uploaded '" + evidenceFile.getOriginalFilename() + "', SHA-256=" + sha256);

            return toResponse(evidenceFile);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read/store uploaded file", e);
        }
    }

    private void enforceQuota(User uploader, long incomingBytes) {
        long used = evidenceFileRepository.sumSizeByUploadedById(uploader.getId());
        if (used + incomingBytes > maxUserQuotaBytes) {
            throw new IllegalArgumentException(
                    "Upload would exceed your storage quota (" + (maxUserQuotaBytes / (1024 * 1024)) + " MB). "
                            + "Contact an admin if you need more space.");
        }
    }

    public byte[] downloadEvidence(String username, UUID evidenceId) {
        EvidenceFile evidenceFile = getOrThrowWithAccess(username, evidenceId);
        byte[] plaintext = decryptForAnalysis(evidenceFile);

        auditLogService.record(username, AuditAction.EVIDENCE_DOWNLOADED, evidenceFile.getEvidenceCase().getId(),
                evidenceId, "Downloaded '" + evidenceFile.getOriginalFilename() + "'");

        return plaintext;
    }

    @Transactional
    public VerificationResponse verifyIntegrity(String username, UUID evidenceId) {
        EvidenceFile evidenceFile = getOrThrowWithAccess(username, evidenceId);
        byte[] ciphertext = readCiphertext(evidenceFile);
        SecretKey caseKey = caseService.getCaseDataKey(evidenceFile.getEvidenceCase());
        byte[] iv = Base64.getDecoder().decode(evidenceFile.getEncryptionIv());

        String recomputedHash;
        boolean passed;
        String message;
        try {
            byte[] plaintext = encryptionService.decryptWithKey(ciphertext, iv, caseKey);
            recomputedHash = hashService.sha256Hex(plaintext);
            passed = recomputedHash.equals(evidenceFile.getSha256Hash());
            message = passed
                    ? "Integrity verified: file is byte-for-byte identical to what was uploaded"
                    : "MISMATCH: recomputed hash differs from the original upload hash - file may have been tampered with";
        } catch (Exception e) {
            recomputedHash = "N/A";
            passed = false;
            message = "Decryption/authentication failed - ciphertext on disk has been altered or corrupted";
        }

        evidenceFile.setLastVerifiedAt(Instant.now().truncatedTo(ChronoUnit.MILLIS));
        evidenceFile.setLastVerificationPassed(passed);
        evidenceFileRepository.save(evidenceFile);

        auditLogService.record(username,
                passed ? AuditAction.EVIDENCE_INTEGRITY_VERIFIED : AuditAction.EVIDENCE_INTEGRITY_FAILED,
                evidenceFile.getEvidenceCase().getId(), evidenceId, message);

        return new VerificationResponse(evidenceId, passed, evidenceFile.getSha256Hash(), recomputedHash, message);
    }

    public EvidenceResponse getMetadata(String username, UUID evidenceId) {
        EvidenceFile evidenceFile = getOrThrowWithAccess(username, evidenceId);
        auditLogService.record(username, AuditAction.EVIDENCE_METADATA_VIEWED,
                evidenceFile.getEvidenceCase().getId(), evidenceId, "Viewed metadata");
        return toResponse(evidenceFile);
    }

    public List<EvidenceResponse> listByCase(String username, UUID caseId) {
        caseService.assertAccess(username, caseId);
        return evidenceFileRepository.findByEvidenceCaseId(caseId).stream()
                .sorted((a, b) -> b.getUploadedAt().compareTo(a.getUploadedAt()))
                .map(this::toResponse)
                .toList();
    }

    /** Search spans all cases, so results are filtered down to only cases the caller can access. */
    public List<EvidenceResponse> search(String username, String query) {
        return evidenceFileRepository
                .findByOriginalFilenameContainingIgnoreCaseOrSha256HashContainingIgnoreCase(query, query)
                .stream()
                .filter(f -> caseService.hasAccess(username, f.getEvidenceCase().getId()))
                .sorted((a, b) -> b.getUploadedAt().compareTo(a.getUploadedAt()))
                .map(this::toResponse)
                .toList();
    }

    /**
     * Structured search: combines a free-text filename/hash substring with optional case,
     * uploader, custody-status, and upload-date-range filters. Every filter is AND-ed together
     * and skipped when null/blank. Still access-scoped the same way as the plain-text search
     * above - a caller only ever sees results from cases they can access.
     */
    public List<EvidenceResponse> search(String username, EvidenceSearchFilters filters) {
        boolean hasTextQuery = filters.q() != null && !filters.q().isBlank();
        List<EvidenceFile> candidates = hasTextQuery
                ? evidenceFileRepository.findByOriginalFilenameContainingIgnoreCaseOrSha256HashContainingIgnoreCase(
                        filters.q(), filters.q())
                : evidenceFileRepository.findAll();

        return candidates.stream()
                .filter(f -> caseService.hasAccess(username, f.getEvidenceCase().getId()))
                .filter(f -> filters.caseId() == null || filters.caseId().equals(f.getEvidenceCase().getId()))
                .filter(f -> filters.uploadedBy() == null || filters.uploadedBy().isBlank()
                        || filters.uploadedBy().equalsIgnoreCase(f.getUploadedBy().getUsername()))
                .filter(f -> filters.custodyStatus() == null || filters.custodyStatus().isBlank()
                        || filters.custodyStatus().equalsIgnoreCase(f.getCustodyStatus().name()))
                .filter(f -> filters.uploadedAfter() == null || !f.getUploadedAt().isBefore(filters.uploadedAfter()))
                .filter(f -> filters.uploadedBefore() == null || !f.getUploadedAt().isAfter(filters.uploadedBefore()))
                .sorted((a, b) -> b.getUploadedAt().compareTo(a.getUploadedAt()))
                .map(this::toResponse)
                .toList();
    }

    @Transactional
    public NoteResponse addNote(String username, UUID evidenceId, String content) {
        EvidenceFile evidenceFile = getOrThrowWithAccess(username, evidenceId);
        EvidenceNote note = EvidenceNote.builder()
                .evidenceFile(evidenceFile)
                .authorUsername(username)
                .content(content)
                .build();
        evidenceNoteRepository.save(note);

        auditLogService.record(username, AuditAction.EVIDENCE_NOTE_ADDED,
                evidenceFile.getEvidenceCase().getId(), evidenceId, "Note added: " + truncate(content, 120));

        return new NoteResponse(note.getId(), note.getAuthorUsername(), note.getContent(), note.getCreatedAt());
    }

    public List<NoteResponse> listNotes(String username, UUID evidenceId) {
        getOrThrowWithAccess(username, evidenceId);
        return evidenceNoteRepository.findByEvidenceFileIdOrderByCreatedAtAsc(evidenceId).stream()
                .map(n -> new NoteResponse(n.getId(), n.getAuthorUsername(), n.getContent(), n.getCreatedAt()))
                .toList();
    }

    public FileTypeResponse analyzeFileType(String username, UUID evidenceId) {
        EvidenceFile evidenceFile = getOrThrowWithAccess(username, evidenceId);
        byte[] plaintext = decryptForAnalysis(evidenceFile);
        var result = forensicAnalysisService.detectFileType(
                plaintext, evidenceFile.getOriginalFilename(), evidenceFile.getContentType());

        auditLogService.record(username, AuditAction.EVIDENCE_ANALYZED,
                evidenceFile.getEvidenceCase().getId(), evidenceId,
                "File-type analysis run - detected: " + result.detectedType()
                        + (result.mismatch() ? " (MISMATCH with claimed extension)" : ""));

        return new FileTypeResponse(result.detectedType(), result.claimedContentType(),
                result.claimedExtension(), result.mismatch(), result.signatureHex());
    }

    public HexDumpResponse hexDump(String username, UUID evidenceId) {
        EvidenceFile evidenceFile = getOrThrowWithAccess(username, evidenceId);
        byte[] plaintext = decryptForAnalysis(evidenceFile);
        int maxBytes = 512;
        List<String> lines = forensicAnalysisService.hexDump(plaintext, maxBytes);

        auditLogService.record(username, AuditAction.EVIDENCE_ANALYZED,
                evidenceFile.getEvidenceCase().getId(), evidenceId, "Hex dump viewed");

        return new HexDumpResponse(lines, Math.min(plaintext.length, maxBytes), plaintext.length);
    }

    public StringsResponse extractStrings(String username, UUID evidenceId) {
        EvidenceFile evidenceFile = getOrThrowWithAccess(username, evidenceId);
        byte[] plaintext = decryptForAnalysis(evidenceFile);
        var result = forensicAnalysisService.extractStrings(plaintext, 4, 200);

        auditLogService.record(username, AuditAction.EVIDENCE_ANALYZED,
                evidenceFile.getEvidenceCase().getId(), evidenceId,
                "Strings extraction run - " + result.totalFound() + " strings found");

        return new StringsResponse(result.strings(), result.totalFound(), result.truncated());
    }

    public SignatureResponse getSignature(String username, UUID evidenceId) {
        EvidenceFile evidenceFile = getOrThrowWithAccess(username, evidenceId);
        User signer = evidenceFile.getUploadedBy();
        boolean verified = signatureService.verify(
                signer.getRsaPublicKey(), evidenceFile.getSha256Hash(), evidenceFile.getSignatureBase64());
        String fingerprint = hashService.sha256Hex(signer.getRsaPublicKey()).substring(0, 16);
        return new SignatureResponse(signer.getUsername(), fingerprint, evidenceFile.getSignatureBase64(), verified);
    }

    @Transactional
    public EvidenceResponse witnessEvidence(String username, UUID evidenceId) {
        EvidenceFile evidenceFile = getOrThrowWithAccess(username, evidenceId);

        if (evidenceFile.getUploadedBy().getUsername().equals(username)) {
            throw new IllegalArgumentException(
                    "You cannot witness your own upload - two-person integrity requires a different investigator");
        }
        if (evidenceFile.getCustodyStatus() == CustodyStatus.WITNESSED) {
            throw new IllegalArgumentException("This evidence has already been witnessed");
        }

        evidenceFile.setWitnessUsername(username);
        evidenceFile.setWitnessedAt(Instant.now().truncatedTo(ChronoUnit.MILLIS));
        evidenceFile.setCustodyStatus(CustodyStatus.WITNESSED);
        evidenceFileRepository.save(evidenceFile);

        auditLogService.record(username, AuditAction.EVIDENCE_WITNESSED,
                evidenceFile.getEvidenceCase().getId(), evidenceId,
                "Witnessed by " + username + " - two-person integrity now satisfied");

        return toResponse(evidenceFile);
    }

    public List<SimilarEvidenceResponse> findSimilar(String username, UUID evidenceId) {
        EvidenceFile target = getOrThrowWithAccess(username, evidenceId);
        Set<String> targetFingerprint = similarityService.stringToFingerprint(target.getFingerprintData());

        return evidenceFileRepository.findAll().stream()
                .filter(f -> !f.getId().equals(evidenceId))
                .filter(f -> caseService.hasAccess(username, f.getEvidenceCase().getId()))
                .filter(f -> f.getFingerprintData() != null && !f.getFingerprintData().isBlank())
                .map(f -> {
                    Set<String> otherFingerprint = similarityService.stringToFingerprint(f.getFingerprintData());
                    double similarity = similarityService.similarityPercent(targetFingerprint, otherFingerprint);
                    return new SimilarEvidenceResponse(f.getId(), f.getOriginalFilename(),
                            f.getEvidenceCase().getCaseNumber(), similarity);
                })
                .filter(r -> r.similarityPercent() >= 15.0)
                .sorted(Comparator.comparingDouble(SimilarEvidenceResponse::similarityPercent).reversed())
                .limit(10)
                .toList();
    }

    /**
     * Evidence is immutable once uploaded - this preserves chain of custody. Deletion is
     * always refused, but the attempt itself is always logged, including who tried and when.
     * This means even an admin cannot quietly remove evidence from the record.
     */
    @Transactional
    public void attemptDelete(String username, UUID evidenceId) {
        EvidenceFile evidenceFile = getOrThrowWithAccess(username, evidenceId);
        auditLogService.record(username, AuditAction.EVIDENCE_DELETE_ATTEMPTED,
                evidenceFile.getEvidenceCase().getId(), evidenceId,
                "Deletion attempted and refused - evidence is immutable once uploaded");
        throw new IllegalStateException(
                "Evidence cannot be deleted to preserve chain of custody. This attempt has been logged.");
    }

    public String getOriginalFilename(UUID evidenceId) {
        return getOrThrow(evidenceId).getOriginalFilename();
    }

    public String getContentType(UUID evidenceId) {
        return getOrThrow(evidenceId).getContentType();
    }

    public EvidenceFile getOrThrow(UUID evidenceId) {
        return evidenceFileRepository.findById(evidenceId)
                .orElseThrow(() -> new IllegalArgumentException("Evidence file not found"));
    }

    /** Loads the evidence file and enforces that the caller has access to its parent case. */
    private EvidenceFile getOrThrowWithAccess(String username, UUID evidenceId) {
        EvidenceFile evidenceFile = getOrThrow(evidenceId);
        if (!caseService.hasAccess(username, evidenceFile.getEvidenceCase().getId())) {
            auditLogService.record(username, AuditAction.CASE_ACCESS_DENIED,
                    evidenceFile.getEvidenceCase().getId(), evidenceId,
                    username + " attempted to access evidence without case assignment");
            throw new AccessDeniedException("You are not assigned to this case");
        }
        return evidenceFile;
    }

    private byte[] decryptForAnalysis(EvidenceFile evidenceFile) {
        byte[] ciphertext = readCiphertext(evidenceFile);
        SecretKey caseKey = caseService.getCaseDataKey(evidenceFile.getEvidenceCase());
        byte[] iv = Base64.getDecoder().decode(evidenceFile.getEncryptionIv());
        return encryptionService.decryptWithKey(ciphertext, iv, caseKey);
    }

    private byte[] readCiphertext(EvidenceFile evidenceFile) {
        try {
            return Files.readAllBytes(Path.of(storageDir).resolve(evidenceFile.getStoredFilename()));
        } catch (IOException e) {
            throw new IllegalStateException("Stored evidence blob is missing from disk - possible data loss", e);
        }
    }

    private String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    private EvidenceResponse toResponse(EvidenceFile f) {
        return new EvidenceResponse(f.getId(), f.getEvidenceCase().getId(), f.getEvidenceCase().getCaseNumber(),
                f.getOriginalFilename(), f.getContentType(), f.getOriginalSizeBytes(), f.getSha256Hash(),
                f.getUploadedBy().getUsername(), f.getUploadedAt(), f.getLastVerifiedAt(), f.getLastVerificationPassed(),
                f.getCustodyStatus().name(), f.getWitnessUsername(), f.getWitnessedAt());
    }
}

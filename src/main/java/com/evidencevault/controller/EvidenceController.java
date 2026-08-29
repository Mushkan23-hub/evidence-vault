package com.evidencevault.controller;

import com.evidencevault.dto.EvidenceDtos.*;
import com.evidencevault.service.EvidenceService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
public class EvidenceController {

    private final EvidenceService evidenceService;

    @PostMapping("/api/cases/{caseId}/evidence")
    public ResponseEntity<EvidenceResponse> upload(Authentication auth,
                                                     @PathVariable UUID caseId,
                                                     @RequestParam("file") MultipartFile file) {
        return ResponseEntity.ok(evidenceService.uploadEvidence(auth.getName(), caseId, file));
    }

    @GetMapping("/api/evidence/{evidenceId}")
    public ResponseEntity<EvidenceResponse> getMetadata(Authentication auth, @PathVariable UUID evidenceId) {
        return ResponseEntity.ok(evidenceService.getMetadata(auth.getName(), evidenceId));
    }

    @GetMapping("/api/evidence/{evidenceId}/download")
    public ResponseEntity<ByteArrayResource> download(Authentication auth, @PathVariable UUID evidenceId) {
        byte[] plaintext = evidenceService.downloadEvidence(auth.getName(), evidenceId);
        String filename = evidenceService.getOriginalFilename(evidenceId);
        String contentType = evidenceService.getContentType(evidenceId);

        ContentDisposition disposition = ContentDisposition.attachment().filename(filename).build();

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                .header(HttpHeaders.CONTENT_TYPE, contentType)
                .body(new ByteArrayResource(plaintext));
    }

    @GetMapping("/api/cases/{caseId}/evidence")
    public ResponseEntity<List<EvidenceResponse>> listForCase(Authentication auth, @PathVariable UUID caseId) {
        return ResponseEntity.ok(evidenceService.listByCase(auth.getName(), caseId));
    }

    @GetMapping("/api/evidence/search")
    public ResponseEntity<List<EvidenceResponse>> search(Authentication auth, @RequestParam("q") String query) {
        return ResponseEntity.ok(evidenceService.search(auth.getName(), query));
    }

    /**
     * Structured search with combinable filters, all optional: free-text q, caseId, uploadedBy
     * (username), status (PENDING_WITNESS/WITNESSED - see CustodyStatus), and an uploadedAfter /
     * uploadedBefore date range (ISO-8601, e.g. 2026-01-01T00:00:00Z).
     */
    @GetMapping("/api/evidence/search/advanced")
    public ResponseEntity<List<EvidenceResponse>> searchAdvanced(
            Authentication auth,
            @RequestParam(value = "q", required = false) String q,
            @RequestParam(value = "caseId", required = false) UUID caseId,
            @RequestParam(value = "uploadedBy", required = false) String uploadedBy,
            @RequestParam(value = "status", required = false) String status,
            @RequestParam(value = "uploadedAfter", required = false)
            @org.springframework.format.annotation.DateTimeFormat(iso = org.springframework.format.annotation.DateTimeFormat.ISO.DATE_TIME) java.time.Instant uploadedAfter,
            @RequestParam(value = "uploadedBefore", required = false)
            @org.springframework.format.annotation.DateTimeFormat(iso = org.springframework.format.annotation.DateTimeFormat.ISO.DATE_TIME) java.time.Instant uploadedBefore) {
        EvidenceSearchFilters filters = new EvidenceSearchFilters(q, caseId, uploadedBy, status, uploadedAfter, uploadedBefore);
        return ResponseEntity.ok(evidenceService.search(auth.getName(), filters));
    }

    @PostMapping("/api/evidence/{evidenceId}/notes")
    public ResponseEntity<NoteResponse> addNote(Authentication auth, @PathVariable UUID evidenceId,
                                                 @jakarta.validation.Valid @RequestBody AddNoteRequest request) {
        return ResponseEntity.ok(evidenceService.addNote(auth.getName(), evidenceId, request.content()));
    }

    @GetMapping("/api/evidence/{evidenceId}/notes")
    public ResponseEntity<List<NoteResponse>> listNotes(Authentication auth, @PathVariable UUID evidenceId) {
        return ResponseEntity.ok(evidenceService.listNotes(auth.getName(), evidenceId));
    }

    @GetMapping("/api/evidence/{evidenceId}/analysis/file-type")
    public ResponseEntity<FileTypeResponse> analyzeFileType(Authentication auth, @PathVariable UUID evidenceId) {
        return ResponseEntity.ok(evidenceService.analyzeFileType(auth.getName(), evidenceId));
    }

    @GetMapping("/api/evidence/{evidenceId}/analysis/hexdump")
    public ResponseEntity<HexDumpResponse> hexDump(Authentication auth, @PathVariable UUID evidenceId) {
        return ResponseEntity.ok(evidenceService.hexDump(auth.getName(), evidenceId));
    }

    @GetMapping("/api/evidence/{evidenceId}/analysis/strings")
    public ResponseEntity<StringsResponse> extractStrings(Authentication auth, @PathVariable UUID evidenceId) {
        return ResponseEntity.ok(evidenceService.extractStrings(auth.getName(), evidenceId));
    }

    @GetMapping("/api/evidence/{evidenceId}/signature")
    public ResponseEntity<SignatureResponse> getSignature(Authentication auth, @PathVariable UUID evidenceId) {
        return ResponseEntity.ok(evidenceService.getSignature(auth.getName(), evidenceId));
    }

    @PostMapping("/api/evidence/{evidenceId}/witness")
    public ResponseEntity<EvidenceResponse> witness(Authentication auth, @PathVariable UUID evidenceId) {
        return ResponseEntity.ok(evidenceService.witnessEvidence(auth.getName(), evidenceId));
    }

    @GetMapping("/api/evidence/{evidenceId}/similar")
    public ResponseEntity<List<SimilarEvidenceResponse>> findSimilar(Authentication auth, @PathVariable UUID evidenceId) {
        return ResponseEntity.ok(evidenceService.findSimilar(auth.getName(), evidenceId));
    }

    @DeleteMapping("/api/evidence/{evidenceId}")
    public ResponseEntity<Void> attemptDelete(Authentication auth, @PathVariable UUID evidenceId) {
        evidenceService.attemptDelete(auth.getName(), evidenceId);
        return ResponseEntity.noContent().build(); // unreachable - attemptDelete always throws
    }

    @PostMapping("/api/evidence/{evidenceId}/verify")
    public ResponseEntity<VerificationResponse> verify(Authentication auth, @PathVariable UUID evidenceId) {
        return ResponseEntity.ok(evidenceService.verifyIntegrity(auth.getName(), evidenceId));
    }
}

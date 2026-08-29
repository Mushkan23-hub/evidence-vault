package com.evidencevault.controller;

import com.evidencevault.dto.AuditDtos.*;
import com.evidencevault.model.AuditAction;
import com.evidencevault.model.AuditLogEntry;
import com.evidencevault.repository.AuditLogRepository;
import com.evidencevault.service.AnomalyDetectionService;
import com.evidencevault.service.AuditLogService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/audit")
@RequiredArgsConstructor
public class AuditController {

    private final AuditLogRepository auditLogRepository;
    private final AuditLogService auditLogService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final ObjectMapper objectMapper;

    @GetMapping("/chain")
    public ResponseEntity<List<AuditEntryResponse>> getChain() {
        List<AuditEntryResponse> entries = auditLogRepository.findAllByOrderBySequenceNumberAsc()
                .stream()
                .map(this::toResponse)
                .toList();
        return ResponseEntity.ok(entries);
    }

    /**
     * Live audit feed: opens a Server-Sent Events stream and pushes each new AuditLogEntry the
     * moment it's recorded, instead of the dashboard having to poll /api/audit/chain on a timer.
     * ADMIN-only, same as the rest of /api/audit/** (see SecurityConfig). Stays open until the
     * client disconnects; an EventSource in the browser reconnects automatically if it drops.
     */
    @GetMapping("/stream")
    public SseEmitter stream() {
        return auditLogService.subscribe();
    }

    @PostMapping("/verify-chain")
    public ResponseEntity<ChainVerificationResponse> verifyChain(Authentication auth) {
        AuditLogService.ChainVerificationResult result = auditLogService.verifyChain();
        // Recording the verification itself is intentionally done AFTER computing the result,
        // so this call doesn't affect the very chain it just checked.
        auditLogService.record(auth.getName(), AuditAction.AUDIT_CHAIN_VERIFIED, null, null,
                "Chain verification run: " + result.message());
        return ResponseEntity.ok(new ChainVerificationResponse(result.intact(), result.lastValidSequence(), result.message()));
    }

    @GetMapping("/anomalies")
    public ResponseEntity<List<AnomalyDetectionService.AnomalyFlag>> anomalies() {
        return ResponseEntity.ok(anomalyDetectionService.detectAnomalies());
    }

    /**
     * Exports the entire hash chain as a downloadable JSON file, so someone can independently
     * re-verify the chain OUTSIDE this application (recompute each entry's SHA-256 over its
     * fields + previousHash, confirm it matches entryHash, confirm entryHash[i] == previousHash[i+1]).
     * This is the strongest "trust but verify" argument the app can make: the verification logic
     * isn't secret and doesn't have to be trusted blindly.
     */
    @GetMapping("/export")
    public ResponseEntity<ByteArrayResource> exportChain(Authentication auth) throws Exception {
        List<AuditEntryResponse> entries = auditLogRepository.findAllByOrderBySequenceNumberAsc()
                .stream()
                .map(this::toResponse)
                .toList();

        Map<String, Object> export = Map.of(
                "exportedAt", Instant.now().toString(),
                "exportedBy", auth.getName(),
                "entryCount", entries.size(),
                "entries", entries
        );

        byte[] json = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(export);

        auditLogService.record(auth.getName(), AuditAction.AUDIT_CHAIN_EXPORTED, null, null,
                "Full audit chain exported (" + entries.size() + " entries)");

        ContentDisposition disposition = ContentDisposition.attachment()
                .filename("audit-chain-export-" + Instant.now().getEpochSecond() + ".json")
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                .contentType(MediaType.APPLICATION_JSON)
                .body(new ByteArrayResource(json));
    }

    private AuditEntryResponse toResponse(AuditLogEntry e) {
        return new AuditEntryResponse(e.getSequenceNumber(), e.getTimestamp(), e.getActorUsername(), e.getAction(),
                e.getRelatedCaseId(), e.getRelatedEvidenceId(), e.getDetails(), e.getPreviousHash(), e.getEntryHash());
    }
}

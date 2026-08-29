package com.evidencevault.controller;

import com.evidencevault.dto.CaseDtos.*;
import com.evidencevault.dto.TimelineDtos.TimelineEvent;
import com.evidencevault.service.CaseService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/cases")
@RequiredArgsConstructor
public class CaseController {

    private final CaseService caseService;

    @PostMapping
    public ResponseEntity<CaseResponse> createCase(Authentication auth, @Valid @RequestBody CreateCaseRequest request) {
        return ResponseEntity.ok(caseService.createCase(auth.getName(), request));
    }

    @GetMapping
    public ResponseEntity<List<CaseResponse>> listCases(Authentication auth) {
        return ResponseEntity.ok(caseService.listCases(auth.getName()));
    }

    @PatchMapping("/{caseId}/status")
    public ResponseEntity<CaseResponse> updateStatus(Authentication auth, @PathVariable UUID caseId,
                                                       @Valid @RequestBody UpdateStatusRequest request) {
        return ResponseEntity.ok(caseService.updateStatus(auth.getName(), caseId, request.status()));
    }

    @PostMapping("/{caseId}/assign")
    public ResponseEntity<CaseResponse> assignInvestigator(Authentication auth, @PathVariable UUID caseId,
                                                             @Valid @RequestBody AssignInvestigatorRequest request) {
        return ResponseEntity.ok(caseService.assignInvestigator(auth.getName(), caseId, request.username()));
    }

    /** Closes the case and revokes every outstanding session for anyone with access to it. */
    @PostMapping("/{caseId}/freeze")
    public ResponseEntity<CaseResponse> freezeCase(Authentication auth, @PathVariable UUID caseId) {
        return ResponseEntity.ok(caseService.closeAndFreeze(auth.getName(), caseId));
    }

    /** Re-wraps the case's data key under the current master key without touching evidence files. */
    @PostMapping("/{caseId}/rotate-key")
    public ResponseEntity<CaseResponse> rotateKey(Authentication auth, @PathVariable UUID caseId) {
        return ResponseEntity.ok(caseService.rotateCaseKey(auth.getName(), caseId));
    }

    @GetMapping("/{caseId}/timeline")
    public ResponseEntity<List<TimelineEvent>> timeline(Authentication auth, @PathVariable UUID caseId) {
        return ResponseEntity.ok(caseService.getTimeline(auth.getName(), caseId));
    }
}

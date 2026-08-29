package com.evidencevault.controller;

import com.evidencevault.service.ReportService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequiredArgsConstructor
public class ReportController {

    private final ReportService reportService;

    @GetMapping("/api/cases/{caseId}/report")
    public ResponseEntity<ByteArrayResource> getReport(Authentication auth, @PathVariable UUID caseId) {
        byte[] pdf = reportService.generateCaseReport(auth.getName(), caseId);
        ContentDisposition disposition = ContentDisposition.attachment()
                .filename("chain-of-custody-" + caseId + ".pdf").build();

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                .contentType(MediaType.APPLICATION_PDF)
                .body(new ByteArrayResource(pdf));
    }
}

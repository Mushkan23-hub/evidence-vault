package com.evidencevault.controller;

import com.evidencevault.dto.DashboardDtos.DashboardStats;
import com.evidencevault.dto.DashboardDtos.RecentActivityItem;
import com.evidencevault.model.AuditLogEntry;
import com.evidencevault.repository.AuditLogRepository;
import com.evidencevault.repository.CaseRepository;
import com.evidencevault.repository.EvidenceFileRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
public class DashboardController {

    private final CaseRepository caseRepository;
    private final EvidenceFileRepository evidenceFileRepository;
    private final AuditLogRepository auditLogRepository;

    @GetMapping("/stats")
    public ResponseEntity<DashboardStats> stats() {
        long totalEvidence = evidenceFileRepository.count();
        long verified = evidenceFileRepository.countByLastVerificationPassedTrue();
        long failed = evidenceFileRepository.countByLastVerificationPassedFalse();
        long pending = totalEvidence - verified - failed;

        return ResponseEntity.ok(new DashboardStats(
                caseRepository.count(),
                totalEvidence,
                verified,
                failed,
                pending,
                auditLogRepository.count()
        ));
    }

    @GetMapping("/recent-activity")
    public ResponseEntity<List<RecentActivityItem>> recentActivity() {
        List<RecentActivityItem> items = auditLogRepository.findTop10ByOrderBySequenceNumberDesc().stream()
                .map(this::toItem)
                .toList();
        return ResponseEntity.ok(items);
    }

    private RecentActivityItem toItem(AuditLogEntry e) {
        return new RecentActivityItem(e.getSequenceNumber(), e.getActorUsername(), e.getAction(),
                e.getDetails(), e.getTimestamp());
    }
}

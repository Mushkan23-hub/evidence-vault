package com.evidencevault.dto;

import com.evidencevault.model.AuditAction;

import java.time.Instant;

public class DashboardDtos {
    public record DashboardStats(
            long totalCases,
            long totalEvidence,
            long verifiedEvidence,
            long failedEvidence,
            long pendingEvidence,
            long auditEntries
    ) {}

    public record RecentActivityItem(
            long sequenceNumber,
            String actorUsername,
            AuditAction action,
            String details,
            Instant timestamp
    ) {}
}

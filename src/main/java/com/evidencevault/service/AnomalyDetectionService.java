package com.evidencevault.service;

import com.evidencevault.model.AuditAction;
import com.evidencevault.model.AuditLogEntry;
import com.evidencevault.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Simple rule-based heuristics, NOT machine learning - flags off-hours evidence downloads and
 * rapid repeated downloads of the same file by the same user. Both are patterns real security
 * monitoring tools watch for, implemented here in a deliberately transparent, explainable way
 * rather than as an opaque model.
 */
@Service
@RequiredArgsConstructor
public class AnomalyDetectionService {

    private static final int OFF_HOURS_START = 0;
    private static final int OFF_HOURS_END = 5;
    private static final int RAPID_ACCESS_THRESHOLD = 3;
    private static final int RAPID_ACCESS_WINDOW_MINUTES = 10;

    private final AuditLogRepository auditLogRepository;

    public List<AnomalyFlag> detectAnomalies() {
        List<AuditLogEntry> downloads = auditLogRepository.findAllByOrderBySequenceNumberAsc().stream()
                .filter(e -> e.getAction() == AuditAction.EVIDENCE_DOWNLOADED)
                .toList();

        List<AnomalyFlag> flags = new ArrayList<>();
        flags.addAll(detectOffHours(downloads));
        flags.addAll(detectRapidAccess(downloads));

        flags.sort(Comparator.comparing(AnomalyFlag::timestamp).reversed());
        return flags;
    }

    private List<AnomalyFlag> detectOffHours(List<AuditLogEntry> downloads) {
        List<AnomalyFlag> flags = new ArrayList<>();
        for (AuditLogEntry e : downloads) {
            int hour = e.getTimestamp().atZone(ZoneOffset.UTC).getHour();
            if (hour >= OFF_HOURS_START && hour < OFF_HOURS_END) {
                flags.add(new AnomalyFlag(e.getActorUsername(), e.getRelatedEvidenceId(),
                        "Off-hours access", "Download occurred at " + hour + ":00 UTC", e.getTimestamp()));
            }
        }
        return flags;
    }

    private List<AnomalyFlag> detectRapidAccess(List<AuditLogEntry> downloads) {
        List<AnomalyFlag> flags = new ArrayList<>();
        Map<String, List<AuditLogEntry>> grouped = new HashMap<>();
        for (AuditLogEntry e : downloads) {
            String key = e.getActorUsername() + "|" + e.getRelatedEvidenceId();
            grouped.computeIfAbsent(key, k -> new ArrayList<>()).add(e);
        }
        for (List<AuditLogEntry> group : grouped.values()) {
            for (int i = 0; i + (RAPID_ACCESS_THRESHOLD - 1) < group.size(); i++) {
                Instant windowStart = group.get(i).getTimestamp();
                Instant windowEnd = group.get(i + RAPID_ACCESS_THRESHOLD - 1).getTimestamp();
                long minutesSpan = ChronoUnit.MINUTES.between(windowStart, windowEnd);
                if (minutesSpan <= RAPID_ACCESS_WINDOW_MINUTES) {
                    AuditLogEntry latest = group.get(i + RAPID_ACCESS_THRESHOLD - 1);
                    flags.add(new AnomalyFlag(latest.getActorUsername(), latest.getRelatedEvidenceId(),
                            "Rapid repeated access",
                            RAPID_ACCESS_THRESHOLD + "+ downloads of the same file within "
                                    + RAPID_ACCESS_WINDOW_MINUTES + " minutes",
                            latest.getTimestamp()));
                }
            }
        }
        return flags;
    }

    public record AnomalyFlag(String actorUsername, UUID evidenceId, String reason, String details, Instant timestamp) {}
}

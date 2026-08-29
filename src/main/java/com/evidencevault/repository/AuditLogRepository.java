package com.evidencevault.repository;

import com.evidencevault.model.AuditLogEntry;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLogEntry, UUID> {
    Optional<AuditLogEntry> findTopByOrderBySequenceNumberDesc();
    List<AuditLogEntry> findAllByOrderBySequenceNumberAsc();
    List<AuditLogEntry> findTop10ByOrderBySequenceNumberDesc();
    List<AuditLogEntry> findByRelatedCaseIdOrderBySequenceNumberAsc(UUID caseId);
}

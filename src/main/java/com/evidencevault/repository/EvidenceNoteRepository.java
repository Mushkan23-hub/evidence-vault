package com.evidencevault.repository;

import com.evidencevault.model.EvidenceNote;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface EvidenceNoteRepository extends JpaRepository<EvidenceNote, UUID> {
    List<EvidenceNote> findByEvidenceFileIdOrderByCreatedAtAsc(UUID evidenceFileId);
}

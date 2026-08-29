package com.evidencevault.repository;

import com.evidencevault.model.EvidenceFile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface EvidenceFileRepository extends JpaRepository<EvidenceFile, UUID> {
    List<EvidenceFile> findByEvidenceCaseId(UUID caseId);
    long countByLastVerificationPassedTrue();
    long countByLastVerificationPassedFalse();
    List<EvidenceFile> findByOriginalFilenameContainingIgnoreCaseOrSha256HashContainingIgnoreCase(
            String filenameQuery, String hashQuery);

    @Query("select coalesce(sum(f.originalSizeBytes), 0) from EvidenceFile f where f.uploadedBy.id = :userId")
    long sumSizeByUploadedById(@Param("userId") UUID userId);
}

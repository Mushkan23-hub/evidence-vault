package com.evidencevault.repository;

import com.evidencevault.model.Case;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface CaseRepository extends JpaRepository<Case, UUID> {
    boolean existsByCaseNumber(String caseNumber);
    Optional<Case> findByCaseNumber(String caseNumber);
}

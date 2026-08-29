package com.evidencevault.repository;

import com.evidencevault.model.ChallengeSubmission;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface ChallengeSubmissionRepository extends JpaRepository<ChallengeSubmission, UUID> {
    boolean existsByChallengeIdAndUsernameAndCorrectTrue(UUID challengeId, String username);
    List<ChallengeSubmission> findByUsernameAndCorrectTrue(String username);
    List<ChallengeSubmission> findByCorrectTrue();
}

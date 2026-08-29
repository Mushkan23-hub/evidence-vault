package com.evidencevault.repository;

import com.evidencevault.model.Challenge;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface ChallengeRepository extends JpaRepository<Challenge, UUID> {
    boolean existsByTitle(String title);
}

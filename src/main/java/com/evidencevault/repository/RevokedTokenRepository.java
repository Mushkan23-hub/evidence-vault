package com.evidencevault.repository;

import com.evidencevault.model.RevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;

public interface RevokedTokenRepository extends JpaRepository<RevokedToken, String> {
    boolean existsByJti(String jti);
    List<RevokedToken> findAllByExpiresAtBefore(Instant cutoff);
}

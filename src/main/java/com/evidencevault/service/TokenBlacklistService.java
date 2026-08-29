package com.evidencevault.service;

import com.evidencevault.model.RevokedToken;
import com.evidencevault.repository.RevokedTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final RevokedTokenRepository revokedTokenRepository;

    @Transactional
    public void revoke(String jti, Instant tokenExpiresAt) {
        if (jti == null) return;
        if (revokedTokenRepository.existsByJti(jti)) return;
        revokedTokenRepository.save(RevokedToken.builder()
                .jti(jti)
                .expiresAt(tokenExpiresAt)
                .build());
    }

    public boolean isRevoked(String jti) {
        return jti != null && revokedTokenRepository.existsByJti(jti);
    }

    /** Once a token's natural expiry has passed it can never be replayed anyway, so its
     *  blacklist row is dead weight - clean it up periodically instead of growing forever. */
    @Scheduled(fixedRate = 6 * 60 * 60 * 1000) // every 6 hours
    @Transactional
    public void purgeExpired() {
        revokedTokenRepository.deleteAll(revokedTokenRepository.findAllByExpiresAtBefore(Instant.now()));
    }
}

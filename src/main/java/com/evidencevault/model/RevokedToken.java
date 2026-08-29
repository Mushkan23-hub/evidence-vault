package com.evidencevault.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * JWTs are stateless by design, so the only way to make "logout" actually revoke a token before
 * its natural expiry is to track revoked token IDs (jti) somewhere the auth filter can check.
 * We persist to the DB (not just an in-memory set) so revocation survives app restarts and works
 * across multiple instances behind a load balancer.
 */
@Entity
@Table(name = "revoked_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RevokedToken {

    @Id
    private String jti;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private Instant revokedAt;

    @PrePersist
    public void prePersist() {
        if (revokedAt == null) {
            revokedAt = Instant.now();
        }
    }
}

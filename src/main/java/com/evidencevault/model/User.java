package com.evidencevault.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password; // bcrypt hash, never store plaintext

    @Column(nullable = false, unique = true)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @Column(nullable = false)
    @Builder.Default
    private int failedLoginAttempts = 0;

    private Instant lockedUntil;

    @Column(columnDefinition = "TEXT")
    private String rsaPublicKey;

    @Column(columnDefinition = "TEXT")
    private String rsaPrivateKey;

    /** Base32 TOTP secret. Set once MFA setup begins, but only enforced once totpEnabled=true. */
    private String totpSecret;

    @Column(nullable = false)
    @Builder.Default
    private boolean totpEnabled = false;

    /**
     * Tokens with an issuedAt before this instant are treated as invalid, even if their natural
     * expiry hasn't passed yet and even if they were never individually blacklisted by jti. This
     * lets us invalidate every outstanding token for a user in one write (e.g. when a case they
     * have access to is closed-and-frozen) instead of enumerating and revoking each jti one by
     * one. Checked in JwtAuthFilter alongside the per-jti blacklist. Null means "no bulk
     * invalidation has ever been issued" - all tokens are considered issued after it.
     */
    private Instant tokensValidAfter;

    /**
     * BCrypt-hashed one-time backup codes for MFA recovery, joined with "|". Never store these in
     * plaintext - each is shown to the user exactly once (at generation time) and hashed the same
     * way passwords are before being persisted. A code is deleted from this list the moment it's
     * used, so each one only ever works once.
     */
    @Column(columnDefinition = "TEXT")
    private String mfaBackupCodesHashed;

    @PrePersist
    public void prePersist() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}

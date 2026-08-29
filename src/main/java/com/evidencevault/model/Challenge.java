package com.evidencevault.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "challenges")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Challenge {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(nullable = false, unique = true)
    private String title;

    @Column(nullable = false, length = 3000)
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ChallengeCategory category;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ChallengeDifficulty difficulty;

    @Column(nullable = false)
    private int points;

    /** SHA-256 of the correct flag text - the plaintext flag is never stored. */
    @Column(nullable = false, length = 64)
    private String flagHash;

    private String artifactFilename;

    @Column(columnDefinition = "TEXT")
    private String artifactBase64;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    public void prePersist() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}

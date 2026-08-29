package com.evidencevault.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "challenge_submissions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ChallengeSubmission {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "challenge_id")
    private Challenge challenge;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private boolean correct;

    @Column(nullable = false, updatable = false)
    private Instant submittedAt;

    @PrePersist
    public void prePersist() {
        if (submittedAt == null) {
            submittedAt = Instant.now();
        }
    }
}

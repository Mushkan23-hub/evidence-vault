package com.evidencevault.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "cases")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Case {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(nullable = false, unique = true)
    private String caseNumber;

    @Column(nullable = false)
    private String title;

    @Column(length = 2000)
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private CaseStatus status = CaseStatus.OPEN;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "created_by")
    private User createdBy;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    /**
     * Investigators explicitly given access to this case, in addition to createdBy and any ADMIN
     * (admins can always see every case). Access checks live in CaseService.assertAccess().
     */
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "case_investigators",
            joinColumns = @JoinColumn(name = "case_id"),
            inverseJoinColumns = @JoinColumn(name = "user_id"))
    @Builder.Default
    private Set<User> assignedInvestigators = new HashSet<>();

    /**
     * Per-case data encryption key (DEK), wrapped (AES-GCM encrypted) with the server's master
     * key and stored alongside its wrap-IV. Envelope encryption: compromising one case's DEK
     * (however that might happen) never exposes other cases' evidence, and the master key itself
     * never directly touches file content. See EncryptionService / EvidenceService.
     */
    @Column(columnDefinition = "TEXT")
    private String wrappedDekBase64;

    private String dekWrapIvBase64;

    @PrePersist
    public void prePersist() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}

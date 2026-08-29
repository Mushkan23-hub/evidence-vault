package com.evidencevault.service;

import com.evidencevault.dto.CaseDtos.*;
import com.evidencevault.dto.TimelineDtos.TimelineEvent;
import com.evidencevault.model.AuditAction;
import com.evidencevault.model.AuditLogEntry;
import com.evidencevault.model.Case;
import com.evidencevault.model.CaseStatus;
import com.evidencevault.model.Role;
import com.evidencevault.model.User;
import com.evidencevault.repository.AuditLogRepository;
import com.evidencevault.repository.CaseRepository;
import com.evidencevault.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CaseService {

    private final CaseRepository caseRepository;
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;
    private final AuditLogRepository auditLogRepository;
    private final EncryptionService encryptionService;

    @Transactional
    public CaseResponse createCase(String username, CreateCaseRequest request) {
        if (caseRepository.existsByCaseNumber(request.caseNumber())) {
            throw new IllegalArgumentException("A case with this case number already exists");
        }
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));

        // Envelope encryption: every case gets its own random AES-256 data key (DEK), which is
        // itself encrypted ("wrapped") with the server's master key before being persisted. Only
        // the wrapped form ever touches the database - the raw DEK exists in memory only for as
        // long as a single encrypt/decrypt operation needs it.
        SecretKey dek = encryptionService.generateDataKey();
        EncryptionService.WrappedKey wrapped = encryptionService.wrapKey(dek);

        Case newCase = Case.builder()
                .caseNumber(request.caseNumber())
                .title(request.title())
                .description(request.description())
                .createdBy(user)
                .wrappedDekBase64(wrapped.wrappedKeyBase64())
                .dekWrapIvBase64(wrapped.ivBase64())
                .build();
        newCase.getAssignedInvestigators().add(user); // creator always has access
        caseRepository.save(newCase);

        auditLogService.record(username, AuditAction.CASE_CREATED, newCase.getId(), null,
                "Case " + newCase.getCaseNumber() + " created: " + newCase.getTitle());

        return toResponse(newCase);
    }

    /** Admins see every case; investigators see only cases they created or were assigned to. */
    public List<CaseResponse> listCases(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));
        List<Case> all = caseRepository.findAll();
        return all.stream()
                .filter(c -> canAccess(user, c))
                .map(this::toResponse)
                .toList();
    }

    public Case getCaseOrThrow(UUID caseId) {
        return caseRepository.findById(caseId)
                .orElseThrow(() -> new IllegalArgumentException("Case not found"));
    }

    /** The raw AES key for this case's evidence, unwrapped from storage on demand. Never cached. */
    public SecretKey getCaseDataKey(Case c) {
        return encryptionService.unwrapKey(c.getWrappedDekBase64(), c.getDekWrapIvBase64());
    }

    /**
     * Throws if the given user cannot access the case: not the creator, not an assigned
     * investigator, and not an admin. Every case- and evidence-scoped read/write should call this
     * before doing anything - unauthorized attempts are themselves audit-logged.
     */
    public Case assertAccess(String username, UUID caseId) {
        Case c = getCaseOrThrow(caseId);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));
        if (!canAccess(user, c)) {
            auditLogService.record(username, AuditAction.CASE_ACCESS_DENIED, caseId, null,
                    username + " attempted to access case " + c.getCaseNumber() + " without assignment");
            throw new org.springframework.security.access.AccessDeniedException(
                    "You are not assigned to this case");
        }
        return c;
    }

    /** Non-throwing variant of assertAccess, for filtering lists (e.g. search results) rather
     *  than rejecting a single-resource request outright. */
    public boolean hasAccess(String username, UUID caseId) {
        User user = userRepository.findByUsername(username).orElse(null);
        Case c = caseRepository.findById(caseId).orElse(null);
        return user != null && c != null && canAccess(user, c);
    }

    private boolean canAccess(User user, Case c) {
        if (user.getRole() == Role.ADMIN) return true;
        if (c.getCreatedBy().getId().equals(user.getId())) return true;
        return c.getAssignedInvestigators().stream().anyMatch(u -> u.getId().equals(user.getId()));
    }

    /** Adds an investigator to a case's access list. Only the case creator or an admin may do this. */
    @Transactional
    public CaseResponse assignInvestigator(String actingUsername, UUID caseId, String investigatorUsername) {
        Case c = getCaseOrThrow(caseId);
        User actor = userRepository.findByUsername(actingUsername)
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));
        if (!canAccess(actor, c) || (actor.getRole() != Role.ADMIN && !c.getCreatedBy().getId().equals(actor.getId()))) {
            throw new org.springframework.security.access.AccessDeniedException(
                    "Only the case creator or an admin may assign investigators");
        }
        User investigator = userRepository.findByUsername(investigatorUsername)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + investigatorUsername));

        c.getAssignedInvestigators().add(investigator);
        caseRepository.save(c);

        auditLogService.record(actingUsername, AuditAction.CASE_INVESTIGATOR_ASSIGNED, caseId, null,
                investigatorUsername + " assigned to case " + c.getCaseNumber() + " by " + actingUsername);

        return toResponse(c);
    }

    @Transactional
    public CaseResponse updateStatus(String username, UUID caseId, String statusText) {
        Case existing = assertAccess(username, caseId);
        CaseStatus newStatus;
        try {
            newStatus = CaseStatus.valueOf(statusText.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("status must be OPEN, CLOSED, or ARCHIVED");
        }
        CaseStatus oldStatus = existing.getStatus();
        existing.setStatus(newStatus);
        caseRepository.save(existing);

        auditLogService.record(username, AuditAction.CASE_STATUS_CHANGED, caseId, null,
                "Case " + existing.getCaseNumber() + " status changed from " + oldStatus + " to " + newStatus);

        return toResponse(existing);
    }

    /**
     * Closes a case and immediately invalidates every outstanding auth token held by anyone with
     * access to it (creator + assigned investigators), rather than waiting for those tokens to
     * expire naturally. Stricter post-closure custody: once frozen, nobody who already had a
     * logged-in session can keep acting on the case's evidence without logging in again - which
     * itself gets audit-logged like any other login. Only the case creator or an admin may freeze
     * a case, same rule as assignInvestigator.
     */
    @Transactional
    public CaseResponse closeAndFreeze(String actingUsername, UUID caseId) {
        Case c = getCaseOrThrow(caseId);
        User actor = userRepository.findByUsername(actingUsername)
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));
        if (!canAccess(actor, c) || (actor.getRole() != Role.ADMIN && !c.getCreatedBy().getId().equals(actor.getId()))) {
            throw new org.springframework.security.access.AccessDeniedException(
                    "Only the case creator or an admin may freeze a case");
        }

        c.setStatus(CaseStatus.CLOSED);
        caseRepository.save(c);

        Instant freezeTime = Instant.now();
        java.util.Set<User> affected = new java.util.HashSet<>(c.getAssignedInvestigators());
        affected.add(c.getCreatedBy());
        for (User u : affected) {
            u.setTokensValidAfter(freezeTime);
        }
        userRepository.saveAll(affected);

        auditLogService.record(actingUsername, AuditAction.CASE_FROZEN, caseId, null,
                "Case " + c.getCaseNumber() + " closed and frozen by " + actingUsername
                        + " - active sessions revoked for: "
                        + affected.stream().map(User::getUsername).sorted().toList());

        return toResponse(c);
    }

    /**
     * Re-wraps a case's data encryption key (DEK) under the current master key, without touching
     * any of the case's encrypted evidence files. Safe to call whether or not a rotation is
     * actually needed - if the DEK is already wrapped with the current key this is a no-op that
     * still succeeds. Only the case creator or an admin may trigger this, same rule as freeze.
     */
    @Transactional
    public CaseResponse rotateCaseKey(String actingUsername, UUID caseId) {
        Case c = getCaseOrThrow(caseId);
        User actor = userRepository.findByUsername(actingUsername)
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));
        if (!canAccess(actor, c) || (actor.getRole() != Role.ADMIN && !c.getCreatedBy().getId().equals(actor.getId()))) {
            throw new org.springframework.security.access.AccessDeniedException(
                    "Only the case creator or an admin may rotate a case's encryption key");
        }

        boolean alreadyCurrent = encryptionService.isWrappedWithCurrentKey(c.getWrappedDekBase64(), c.getDekWrapIvBase64());

        // Unwrap with whichever key actually wraps it today (current or a retired one), then
        // re-wrap fresh under the current master key with a brand new random IV. The evidence
        // files themselves are untouched - they're still encrypted under the same unchanged DEK,
        // only the DEK's own wrapper moves forward.
        SecretKey dek = encryptionService.unwrapKey(c.getWrappedDekBase64(), c.getDekWrapIvBase64());
        EncryptionService.WrappedKey rewrapped = encryptionService.wrapKey(dek);
        c.setWrappedDekBase64(rewrapped.wrappedKeyBase64());
        c.setDekWrapIvBase64(rewrapped.ivBase64());
        caseRepository.save(c);

        auditLogService.record(actingUsername, AuditAction.CASE_KEY_ROTATED, caseId, null,
                alreadyCurrent
                        ? "Case " + c.getCaseNumber() + " DEK re-wrapped under current master key (was already current)"
                        : "Case " + c.getCaseNumber() + " DEK rotated onto the current master key from a retired one");

        return toResponse(c);
    }

    public List<TimelineEvent> getTimeline(String username, UUID caseId) {
        assertAccess(username, caseId);
        return auditLogRepository.findByRelatedCaseIdOrderBySequenceNumberAsc(caseId).stream()
                .map(this::toTimelineEvent)
                .toList();
    }

    private TimelineEvent toTimelineEvent(AuditLogEntry e) {
        return new TimelineEvent(e.getAction().name(), e.getActorUsername(), e.getDetails(), e.getTimestamp());
    }

    private CaseResponse toResponse(Case c) {
        return new CaseResponse(c.getId(), c.getCaseNumber(), c.getTitle(), c.getDescription(),
                c.getStatus().name(), c.getCreatedBy().getUsername(), c.getCreatedAt(),
                c.getAssignedInvestigators().stream().map(User::getUsername).sorted().toList());
    }
}

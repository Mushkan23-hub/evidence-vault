package com.evidencevault.service;

import com.evidencevault.model.AuditAction;
import com.evidencevault.model.AuditLogEntry;
import com.evidencevault.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
@RequiredArgsConstructor
public class AuditLogService {

    private static final String GENESIS_HASH = "0".repeat(64);

    private final AuditLogRepository auditLogRepository;
    private final HashService hashService;

    /**
     * Live subscribers to the audit feed (POST-connect admins hitting /api/audit/stream), each
     * pushed a new event the moment record() appends a fresh entry - the "live/real-time audit
     * feed" the README used to list as not-yet-implemented. Server-Sent Events rather than
     * WebSocket: one-directional (server -> admin dashboard) is all this needs, it rides on plain
     * HTTP so it works through the same Bearer-JWT auth as every other endpoint, and it needs no
     * extra client library. In-memory only, same caveat as RateLimitFilter's default backend: in
     * a multi-instance deployment an admin only sees events recorded by the instance they're
     * connected to. CopyOnWriteArrayList because writes (connect/disconnect) are rare compared to
     * the read-heavy broadcast on every audit record().
     */
    private final List<SseEmitter> subscribers = new CopyOnWriteArrayList<>();

    public SseEmitter subscribe() {
        SseEmitter emitter = new SseEmitter(0L); // no timeout - stays open until the client disconnects
        subscribers.add(emitter);
        emitter.onCompletion(() -> subscribers.remove(emitter));
        emitter.onTimeout(() -> subscribers.remove(emitter));
        emitter.onError(e -> subscribers.remove(emitter));
        return emitter;
    }

    /**
     * Appends a new entry to the tamper-evident log. Synchronized so sequence numbers
     * and the hash chain never race under concurrent requests.
     */
    @Transactional
    public synchronized AuditLogEntry record(String actorUsername, AuditAction action,
                                              UUID caseId, UUID evidenceId, String details) {
        AuditLogEntry previous = auditLogRepository.findTopByOrderBySequenceNumberDesc().orElse(null);
        long nextSeq = previous == null ? 0 : previous.getSequenceNumber() + 1;
        String previousHash = previous == null ? GENESIS_HASH : previous.getEntryHash();

        // Truncated to millis: databases generally don't preserve nanosecond precision,
        // so hashing at full Instant precision would make the hash unrecomputable after
        // the entry round-trips through storage. Truncating here keeps write-time and
        // read-time hashes consistent.
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        String entryHash = computeEntryHash(nextSeq, now, actorUsername, action, caseId, evidenceId, details, previousHash);

        AuditLogEntry entry = AuditLogEntry.builder()
                .sequenceNumber(nextSeq)
                .timestamp(now)
                .actorUsername(actorUsername)
                .action(action)
                .relatedCaseId(caseId)
                .relatedEvidenceId(evidenceId)
                .details(details)
                .previousHash(previousHash)
                .entryHash(entryHash)
                .build();

        AuditLogEntry saved = auditLogRepository.save(entry);
        broadcast(saved);
        return saved;
    }

    /** Best-effort push to every connected /api/audit/stream subscriber. A dead/slow emitter is
     *  dropped rather than allowed to block or fail the audit write it's piggybacking on. */
    private void broadcast(AuditLogEntry entry) {
        if (subscribers.isEmpty()) return;
        for (SseEmitter emitter : subscribers) {
            try {
                emitter.send(SseEmitter.event().name("audit-entry").data(entry));
            } catch (Exception e) {
                subscribers.remove(emitter);
            }
        }
    }

    /**
     * Walks the entire chain from genesis and recomputes every hash.
     * Returns false the moment any entry's recomputed hash doesn't match what's
     * stored, or any previousHash pointer doesn't match the prior entry's hash -
     * either case means a row was edited, deleted, or reordered after the fact.
     */
    public ChainVerificationResult verifyChain() {
        List<AuditLogEntry> entries = auditLogRepository.findAllByOrderBySequenceNumberAsc();
        String expectedPreviousHash = GENESIS_HASH;

        for (AuditLogEntry entry : entries) {
            if (!entry.getPreviousHash().equals(expectedPreviousHash)) {
                return new ChainVerificationResult(false, entry.getSequenceNumber(),
                        "previousHash pointer broken - a prior entry was likely altered or deleted");
            }
            String recomputed = computeEntryHash(entry.getSequenceNumber(), entry.getTimestamp(),
                    entry.getActorUsername(), entry.getAction(), entry.getRelatedCaseId(),
                    entry.getRelatedEvidenceId(), entry.getDetails(), entry.getPreviousHash());
            if (!recomputed.equals(entry.getEntryHash())) {
                return new ChainVerificationResult(false, entry.getSequenceNumber(),
                        "stored entryHash does not match recomputed hash - this entry's content was altered");
            }
            expectedPreviousHash = entry.getEntryHash();
        }
        return new ChainVerificationResult(true, entries.isEmpty() ? -1 : entries.get(entries.size() - 1).getSequenceNumber(),
                "chain intact - all " + entries.size() + " entries verified");
    }

    private String computeEntryHash(long seq, Instant timestamp, String actor, AuditAction action,
                                     UUID caseId, UUID evidenceId, String details, String previousHash) {
        String canonical = seq + "|" + timestamp + "|" + actor + "|" + action + "|"
                + (caseId == null ? "-" : caseId) + "|" + (evidenceId == null ? "-" : evidenceId) + "|"
                + (details == null ? "-" : details) + "|" + previousHash;
        return hashService.sha256Hex(canonical);
    }

    public record ChainVerificationResult(boolean intact, long lastValidSequence, String message) {}
}

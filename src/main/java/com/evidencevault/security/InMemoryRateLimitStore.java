package com.evidencevault.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default rate-limit backend: an in-process sliding-window counter per key. Fine for a single
 * instance, but limits apply per-instance only - if this app ever runs behind a load balancer
 * with multiple instances, each instance enforces the limit independently, so the *effective*
 * limit is roughly (per-instance limit x instance count). Switch to RedisRateLimitStore
 * (evidencevault.rate-limit.backend=redis) for a limit that's shared across every instance.
 */
@Component
@ConditionalOnProperty(name = "evidencevault.rate-limit.backend", havingValue = "memory", matchIfMissing = true)
public class InMemoryRateLimitStore implements RateLimitStore {

    private final Map<String, Deque<Instant>> hits = new ConcurrentHashMap<>();

    @Override
    public boolean isOverLimit(String key, int maxRequests, int windowSeconds) {
        Instant now = Instant.now();
        Instant windowStart = now.minusSeconds(windowSeconds);
        Deque<Instant> timestamps = hits.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (timestamps) {
            while (!timestamps.isEmpty() && timestamps.peekFirst().isBefore(windowStart)) {
                timestamps.pollFirst();
            }
            if (timestamps.size() >= maxRequests) {
                return true;
            }
            timestamps.addLast(now);
            return false;
        }
    }
}

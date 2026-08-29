package com.evidencevault.security;

/**
 * Abstracts *where* rate-limit hit counts live, independent of RateLimitFilter's rules. Two
 * implementations: InMemoryRateLimitStore (default, per-instance, zero extra infra) and
 * RedisRateLimitStore (shared across every app instance behind a load balancer - see README
 * "Distributed rate limiting"). Selected via evidencevault.rate-limit.backend.
 */
public interface RateLimitStore {

    /**
     * Records one hit for {@code key} and reports whether that pushes it over {@code maxRequests}
     * within the trailing {@code windowSeconds}. Implementations decide their own precision
     * (sliding vs fixed window) - callers only need the over/under-limit verdict.
     */
    boolean isOverLimit(String key, int maxRequests, int windowSeconds);
}

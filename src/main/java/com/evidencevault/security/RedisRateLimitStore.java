package com.evidencevault.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Distributed rate-limit backend: every app instance increments the same Redis counter, so the
 * limit is enforced globally rather than per-instance - see README "Distributed rate limiting".
 * Fixed-window algorithm (not sliding): the key is scoped to the current windowSeconds-sized
 * bucket (now / windowSeconds) and the first hit in a bucket sets its TTL. Simpler and cheaper
 * than a sliding-window log, at the cost of letting up to ~2x the limit through right at a window
 * boundary - an acceptable trade-off for blunting brute-force/enumeration, which is what this
 * exists for; it is not meant to be an exact quota system.
 *
 * Activate with evidencevault.rate-limit.backend=redis and REDIS_HOST/REDIS_PORT (or
 * spring.data.redis.* directly). Enabling this without a reachable Redis will make every
 * rate-limited request fail - see failOpen note on isOverLimit.
 */
@Component
@ConditionalOnProperty(name = "evidencevault.rate-limit.backend", havingValue = "redis")
public class RedisRateLimitStore implements RateLimitStore {

    private final StringRedisTemplate redisTemplate;

    public RedisRateLimitStore(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public boolean isOverLimit(String key, int maxRequests, int windowSeconds) {
        long bucket = System.currentTimeMillis() / 1000 / windowSeconds;
        String redisKey = "ratelimit:" + key + ":" + bucket;
        try {
            Long count = redisTemplate.opsForValue().increment(redisKey);
            if (count != null && count == 1L) {
                redisTemplate.expire(redisKey, Duration.ofSeconds(windowSeconds + 1L));
            }
            return count != null && count > maxRequests;
        } catch (Exception e) {
            // Fail OPEN, not closed: if Redis itself is unreachable, a rate limiter outage
            // shouldn't also take down every login/upload/download in the app. The per-account
            // lockout in AuthService and this filter's own in-memory fallback risk are both still
            // there as a second line of defense against brute force even if this check is down.
            return false;
        }
    }
}

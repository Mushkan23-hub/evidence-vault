package com.evidencevault.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.regex.Pattern;

/**
 * Applies per-endpoint request-rate rules using whichever RateLimitStore is active (in-memory by
 * default, or Redis for a multi-instance deployment - see evidencevault.rate-limit.backend and
 * RedisRateLimitStore). It exists to blunt brute-force and enumeration attacks that AuthService's
 * per-account lockout doesn't cover on its own (e.g. hammering /api/auth/login with many
 * DIFFERENT usernames, or scripting downloads/uploads against arbitrary evidence IDs).
 */
@Component
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimitStore rateLimitStore;

    private record Rule(Pattern pathPattern, String method, int maxRequests, int windowSeconds) {}

    private final Rule[] rules = new Rule[] {
            // Login: generous account-lockout already exists in AuthService, this just stops
            // high-volume username enumeration / credential stuffing against the endpoint itself.
            new Rule(Pattern.compile("^/api/auth/login$"), "POST", 20, 60),
            new Rule(Pattern.compile("^/api/auth/register$"), "POST", 10, 60),
            // Evidence upload/download: prevents scripted mass-download/upload abuse.
            new Rule(Pattern.compile("^/api/cases/[^/]+/evidence$"), "POST", 30, 60),
            new Rule(Pattern.compile("^/api/evidence/[^/]+/download$"), "GET", 30, 60),
    };

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                     @NonNull HttpServletResponse response,
                                     @NonNull FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        String method = request.getMethod();

        for (int i = 0; i < rules.length; i++) {
            Rule rule = rules[i];
            if (rule.method().equals(method) && rule.pathPattern().matcher(path).matches()) {
                String clientKey = i + "|" + clientIp(request);
                if (rateLimitStore.isOverLimit(clientKey, rule.maxRequests(), rule.windowSeconds())) {
                    response.setStatus(429); // 429 Too Many Requests
                    response.setContentType("application/json");
                    response.getWriter().write(
                            "{\"status\":429,\"error\":\"TOO_MANY_REQUESTS\",\"message\":\"Rate limit exceeded for this endpoint - please slow down and try again shortly.\"}");
                    return;
                }
                break; // a request only matches one rule
            }
        }

        filterChain.doFilter(request, response);
    }

    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}

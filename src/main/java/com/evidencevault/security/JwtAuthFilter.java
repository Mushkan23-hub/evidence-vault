package com.evidencevault.security;

import com.evidencevault.repository.UserRepository;
import com.evidencevault.service.TokenBlacklistService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final TokenBlacklistService tokenBlacklistService;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                     @NonNull HttpServletResponse response,
                                     @NonNull FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);
        try {
            String username = jwtUtil.extractUsername(token);
            String jti = jwtUtil.extractJti(token);
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                if (jwtUtil.isTokenValid(token, username) && !tokenBlacklistService.isRevoked(jti)
                        && !isBulkInvalidated(username, jwtUtil.extractIssuedAt(token))) {
                    String role = jwtUtil.extractRole(token);
                    var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));
                    var authToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception ignored) {
            // Invalid/expired token -> request proceeds unauthenticated and gets rejected downstream
        }

        filterChain.doFilter(request, response);
    }

    /**
     * True if this token was issued before the user's tokensValidAfter watermark, meaning it was
     * bulk-invalidated (e.g. by a case freeze) even though it's neither expired nor individually
     * blacklisted by jti. Fails open to "not invalidated" if the user can't be found, since an
     * unknown user will simply fail downstream authorization anyway.
     */
    private boolean isBulkInvalidated(String username, Instant tokenIssuedAt) {
        return userRepository.findByUsername(username)
                .map(u -> u.getTokensValidAfter() != null && tokenIssuedAt.isBefore(u.getTokensValidAfter()))
                .orElse(false);
    }
}

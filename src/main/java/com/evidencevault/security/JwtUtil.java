package com.evidencevault.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import java.util.function.Function;

@Component
public class JwtUtil {

    private final SecretKey signingKey;
    private final long expirationMillis;

    public JwtUtil(@Value("${evidencevault.jwt.secret-base64}") String secretBase64,
                    @Value("${evidencevault.jwt.expiration-minutes}") long expirationMinutes) {
        this.signingKey = Keys.hmacShaKeyFor(java.util.Base64.getDecoder().decode(secretBase64));
        this.expirationMillis = expirationMinutes * 60 * 1000;
    }

    public String generateToken(String username, String role) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMillis);
        return Jwts.builder()
                .id(UUID.randomUUID().toString()) // jti - lets a single token be individually revoked (logout)
                .subject(username)
                .claim("role", role)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(signingKey)
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractRole(String token) {
        return extractClaim(token, claims -> claims.get("role", String.class));
    }

    public String extractJti(String token) {
        return extractClaim(token, Claims::getId);
    }

    public Instant extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration).toInstant();
    }

    public Instant extractIssuedAt(String token) {
        return extractClaim(token, Claims::getIssuedAt).toInstant();
    }

    public boolean isTokenValid(String token, String expectedUsername) {
        try {
            String username = extractUsername(token);
            return username.equals(expectedUsername) && !isExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    private <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return resolver.apply(claims);
    }
}

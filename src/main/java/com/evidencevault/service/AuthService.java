package com.evidencevault.service;

import com.evidencevault.dto.AuthDtos.*;
import com.evidencevault.exception.MfaRequiredException;
import com.evidencevault.model.AuditAction;
import com.evidencevault.model.Role;
import com.evidencevault.model.User;
import com.evidencevault.repository.UserRepository;
import com.evidencevault.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCKOUT_MINUTES = 15;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuditLogService auditLogService;
    private final SignatureService signatureService;
    private final TotpService totpService;
    private final TokenBlacklistService tokenBlacklistService;
    private final com.evidencevault.repository.EvidenceFileRepository evidenceFileRepository;
    private final EncryptionService encryptionService;
    

    @org.springframework.beans.factory.annotation.Value("${evidencevault.storage.max-user-quota-bytes:5368709120}")
    private long maxUserQuotaBytes;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new IllegalArgumentException("Username already taken");
        }
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already registered");
        }

        // SECURITY: public self-registration can NEVER grant ADMIN, regardless of what the
        // request body asks for - only admins can view/verify the audit chain, so letting anyone
        // register as ADMIN would defeat that access control entirely. Promotion requires an
        // existing admin to call promoteToAdmin() below.
        User user = User.builder()
                .username(request.username())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.INVESTIGATOR)
                .build();

        SignatureService.KeyPairData keyPair = signatureService.generateKeyPair();
        user.setRsaPublicKey(keyPair.publicKeyBase64());
        user.setRsaPrivateKey(encryptionService.encryptStringWithMasterKey(keyPair.privateKeyBase64()));

        userRepository.save(user);

        auditLogService.record(user.getUsername(), AuditAction.USER_REGISTERED, null, null,
                "New user registered with role " + user.getRole());

        String token = jwtUtil.generateToken(user.getUsername(), user.getRole().name());
        return new AuthResponse(token, user.getUsername(), user.getRole().name());
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> {
                    auditLogService.record(request.username(), AuditAction.LOGIN_FAILURE, null, null,
                            "Login attempt for unknown username");
                    return new BadCredentialsException("Invalid username or password");
                });

        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);

        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(now)) {
            long minutesLeft = ChronoUnit.MINUTES.between(now, user.getLockedUntil()) + 1;
            throw new LockedException(
                    "Account locked due to repeated failed logins. Try again in " + minutesLeft + " minute(s).");
        }

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);

            if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
                user.setLockedUntil(now.plus(LOCKOUT_MINUTES, ChronoUnit.MINUTES));
                user.setFailedLoginAttempts(0);
                userRepository.save(user);
                auditLogService.record(user.getUsername(), AuditAction.ACCOUNT_LOCKED, null, null,
                        "Account locked for " + LOCKOUT_MINUTES + " minutes after " + MAX_FAILED_ATTEMPTS + " failed attempts");
                throw new LockedException(
                        "Too many failed attempts. Account locked for " + LOCKOUT_MINUTES + " minutes.");
            }

            userRepository.save(user);
            auditLogService.record(user.getUsername(), AuditAction.LOGIN_FAILURE, null, null,
                    "Incorrect password (attempt " + user.getFailedLoginAttempts() + " of " + MAX_FAILED_ATTEMPTS + ")");
            throw new BadCredentialsException("Invalid username or password");
        }

        if (user.getFailedLoginAttempts() > 0 || user.getLockedUntil() != null) {
            user.setFailedLoginAttempts(0);
            user.setLockedUntil(null);
            userRepository.save(user);
        }

        // Password was correct. If this account has TOTP MFA enabled (ADMIN accounts are
        // encouraged to enable it, since ADMIN is the only role that can view the audit chain),
        // a second factor is required before a token is issued.
        if (user.isTotpEnabled()) {
            boolean totpProvided = request.totpCode() != null && !request.totpCode().isBlank();
            boolean backupProvided = request.backupCode() != null && !request.backupCode().isBlank();

            if (!totpProvided && !backupProvided) {
                auditLogService.record(user.getUsername(), AuditAction.LOGIN_MFA_REQUIRED, null, null,
                        "Password correct, awaiting TOTP code");
                throw new MfaRequiredException("Password correct - enter your 6-digit authenticator code to continue");
            }

            if (totpProvided) {
                if (!totpService.verifyCode(user.getTotpSecret(), request.totpCode())) {
                    auditLogService.record(user.getUsername(), AuditAction.LOGIN_MFA_FAILURE, null, null,
                            "Incorrect TOTP code");
                    throw new BadCredentialsException("Incorrect authenticator code");
                }
            } else {
                if (!consumeBackupCode(user, request.backupCode())) {
                    auditLogService.record(user.getUsername(), AuditAction.LOGIN_MFA_FAILURE, null, null,
                            "Incorrect or already-used MFA backup code");
                    throw new BadCredentialsException("Incorrect or already-used backup code");
                }
                userRepository.save(user);
                auditLogService.record(user.getUsername(), AuditAction.MFA_BACKUP_CODE_USED, null, null,
                        "Logged in with an MFA backup code instead of the authenticator app - "
                                + countRemainingBackupCodes(user) + " code(s) remaining");
            }
        }

        auditLogService.record(user.getUsername(), AuditAction.LOGIN_SUCCESS, null, null, "Successful login");

        String token = jwtUtil.generateToken(user.getUsername(), user.getRole().name());
        return new AuthResponse(token, user.getUsername(), user.getRole().name());
    }

    /** Revokes the presented token immediately rather than waiting for its natural expiry. */
    @Transactional
    public void logout(String username, String rawToken) {
        String jti = jwtUtil.extractJti(rawToken);
        Instant expiry = jwtUtil.extractExpiration(rawToken);
        tokenBlacklistService.revoke(jti, expiry);
        auditLogService.record(username, AuditAction.LOGOUT, null, null, "User logged out - token revoked");
    }

    /**
     * Promotes an existing INVESTIGATOR to ADMIN. Only an existing ADMIN may call this
     * (enforced by @PreAuthorize on the controller) - this is the only path to ADMIN now that
     * public self-registration always creates INVESTIGATOR accounts.
     */
    @Transactional
    public MeResponse promoteToAdmin(String adminUsername, String targetUsername) {
        User target = userRepository.findByUsername(targetUsername)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + targetUsername));
        if (target.getRole() == Role.ADMIN) {
            throw new IllegalArgumentException(targetUsername + " is already an admin");
        }
        target.setRole(Role.ADMIN);
        userRepository.save(target);

        auditLogService.record(adminUsername, AuditAction.USER_PROMOTED, null, null,
                targetUsername + " promoted to ADMIN by " + adminUsername);

        return new MeResponse(target.getUsername(), target.getEmail(), target.getRole().name(), target.getCreatedAt(),
                evidenceFileRepository.sumSizeByUploadedById(target.getId()), maxUserQuotaBytes);
    }

    /** Step 1 of enabling MFA: generate and store a secret, return the otpauth:// URI to render as a QR code. */
    @Transactional
    public MfaSetupResponse beginMfaSetup(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));
        String secret = totpService.generateSecretBase32();
        user.setTotpSecret(secret);
        user.setTotpEnabled(false); // not enabled until confirmed with a valid code
        userRepository.save(user);
        return new MfaSetupResponse(secret, totpService.buildOtpAuthUri(secret, username));
    }

    /** Step 2: user proves they've correctly configured their authenticator app before MFA is enforced.
     *  Also (re)generates a fresh set of one-time backup codes, shown to the caller exactly once. */
    @Transactional
    public BackupCodesResponse confirmMfaSetup(String username, String code) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));
        if (user.getTotpSecret() == null) {
            throw new IllegalArgumentException("MFA setup was not started - call /api/auth/mfa/setup first");
        }
        if (!totpService.verifyCode(user.getTotpSecret(), code)) {
            throw new IllegalArgumentException("Incorrect code - check your authenticator app and try again");
        }
        user.setTotpEnabled(true);
        java.util.List<String> plainCodes = generateAndStoreBackupCodes(user);
        userRepository.save(user);
        auditLogService.record(username, AuditAction.MFA_ENABLED, null, null, "TOTP MFA enabled");
        return new BackupCodesResponse(plainCodes);
    }

    /** Invalidates all existing backup codes and issues a fresh set. Requires MFA to already be
     *  enabled - there's nothing to recover into otherwise. */
    @Transactional
    public BackupCodesResponse regenerateBackupCodes(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));
        if (!user.isTotpEnabled()) {
            throw new IllegalArgumentException("MFA is not enabled on this account");
        }
        java.util.List<String> plainCodes = generateAndStoreBackupCodes(user);
        userRepository.save(user);
        auditLogService.record(username, AuditAction.MFA_BACKUP_CODES_REGENERATED, null, null,
                "MFA backup codes regenerated - all previous backup codes are now invalid");
        return new BackupCodesResponse(plainCodes);
    }

    private java.util.List<String> generateAndStoreBackupCodes(User user) {
        java.util.List<String> plainCodes = totpService.generateBackupCodes(10);
        String hashedJoined = plainCodes.stream()
                .map(passwordEncoder::encode)
                .reduce((a, b) -> a + "|" + b)
                .orElse("");
        user.setMfaBackupCodesHashed(hashedJoined);
        return plainCodes;
    }

    /** Checks the presented code against the user's remaining hashed backup codes and, if it
     *  matches, removes that one so it can never be reused. Does not save - caller must save. */
    private boolean consumeBackupCode(User user, String presentedCode) {
        String stored = user.getMfaBackupCodesHashed();
        if (stored == null || stored.isBlank()) return false;
        java.util.List<String> hashes = new java.util.ArrayList<>(java.util.List.of(stored.split("\\|")));
        for (String hash : hashes) {
            if (passwordEncoder.matches(presentedCode.trim().toUpperCase(), hash)) {
                hashes.remove(hash);
                user.setMfaBackupCodesHashed(String.join("|", hashes));
                return true;
            }
        }
        return false;
    }

    private int countRemainingBackupCodes(User user) {
        String stored = user.getMfaBackupCodesHashed();
        if (stored == null || stored.isBlank()) return 0;
        return stored.split("\\|").length;
    }

    public MeResponse getMe(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));
        long used = evidenceFileRepository.sumSizeByUploadedById(user.getId());
        return new MeResponse(user.getUsername(), user.getEmail(), user.getRole().name(), user.getCreatedAt(),
                used, maxUserQuotaBytes);
    }

    @Transactional
    public void changePassword(String username, String currentPassword, String newPassword) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));

        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new BadCredentialsException("Current password is incorrect");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        auditLogService.record(username, AuditAction.PASSWORD_CHANGED, null, null, "Password changed by user");
    }
}

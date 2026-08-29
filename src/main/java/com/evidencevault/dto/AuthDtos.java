package com.evidencevault.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public class AuthDtos {

    /**
     * Usernames are restricted to a safe charset. Two reasons: (1) usernames flow, unescaped in
     * places server-side (audit "actorUsername" is also written for unauthenticated login attempts
     * using attacker-supplied text), so allowing arbitrary characters would open a stored-XSS path
     * in the frontend; (2) it keeps display consistent across cases, evidence, notes, and the
     * leaderboard.
     */
    public static final String USERNAME_PATTERN = "^[a-zA-Z0-9_.-]{3,50}$";

    public record RegisterRequest(
            @NotBlank @Pattern(regexp = USERNAME_PATTERN,
                    message = "username may only contain letters, numbers, underscore, dot, or hyphen (3-50 chars)")
            String username,
            @NotBlank @Email String email,
            @NotBlank @Size(min = 8, message = "password must be at least 8 characters") String password,
            /**
             * Deliberately IGNORED for public self-registration - see AuthService.register().
             * Kept on the DTO only so old clients/scripts don't fail validation; every new account
             * is created as INVESTIGATOR regardless of what's sent here. Promotion to ADMIN requires
             * an existing admin to call POST /api/auth/users/promote.
             */
            String role
    ) {}

    public record LoginRequest(
            @NotBlank String username,
            @NotBlank String password,
            /** Required only when logging into an account that has TOTP MFA enabled (admins). */
            String totpCode,
            /** Alternative to totpCode: a single-use MFA backup code, for when the authenticator
             *  device is lost. Checked only if totpCode is blank and MFA is enabled. */
            String backupCode
    ) {}

    public record AuthResponse(
            String token,
            String username,
            String role
    ) {}

    public record MeResponse(
            String username,
            String email,
            String role,
            Instant createdAt,
            long storageUsedBytes,
            long storageQuotaBytes
    ) {}

    public record ChangePasswordRequest(
            @NotBlank String currentPassword,
            @NotBlank @Size(min = 8, message = "new password must be at least 8 characters") String newPassword
    ) {}

    public record MfaSetupResponse(
            String secretBase32,
            String otpAuthUri // render as a QR code client-side, or type secretBase32 manually
    ) {}

    public record MfaConfirmRequest(
            @NotBlank @Pattern(regexp = "\\d{6}", message = "code must be 6 digits") String code
    ) {}

    /** Returned once, right after MFA is confirmed or codes are regenerated. Not retrievable
     *  again afterwards - only hashes are kept server-side, same as passwords. */
    public record BackupCodesResponse(
            java.util.List<String> backupCodes
    ) {}

    public record PromoteRequest(
            @NotBlank String username
    ) {}
}

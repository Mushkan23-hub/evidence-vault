package com.evidencevault.controller;

import com.evidencevault.dto.AuthDtos.*;
import com.evidencevault.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(Authentication auth, @RequestHeader("Authorization") String authHeader) {
        String rawToken = authHeader.substring(7); // strip "Bearer "
        authService.logout(auth.getName(), rawToken);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    public ResponseEntity<MeResponse> me(Authentication auth) {
        return ResponseEntity.ok(authService.getMe(auth.getName()));
    }

    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(Authentication auth, @Valid @RequestBody ChangePasswordRequest request) {
        authService.changePassword(auth.getName(), request.currentPassword(), request.newPassword());
        return ResponseEntity.noContent().build();
    }

    /** ADMIN-only: promotes another user to ADMIN. The only way to create an admin post-bootstrap. */
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/users/promote")
    public ResponseEntity<MeResponse> promote(Authentication auth, @Valid @RequestBody PromoteRequest request) {
        return ResponseEntity.ok(authService.promoteToAdmin(auth.getName(), request.username()));
    }

    @PostMapping("/mfa/setup")
    public ResponseEntity<MfaSetupResponse> beginMfaSetup(Authentication auth) {
        return ResponseEntity.ok(authService.beginMfaSetup(auth.getName()));
    }

    @PostMapping("/mfa/confirm")
    public ResponseEntity<BackupCodesResponse> confirmMfaSetup(Authentication auth, @Valid @RequestBody MfaConfirmRequest request) {
        return ResponseEntity.ok(authService.confirmMfaSetup(auth.getName(), request.code()));
    }

    /** Invalidates all existing backup codes and issues a fresh set of 10. Use if the old set is
     *  lost, exhausted, or possibly compromised. */
    @PostMapping("/mfa/backup-codes/regenerate")
    public ResponseEntity<BackupCodesResponse> regenerateBackupCodes(Authentication auth) {
        return ResponseEntity.ok(authService.regenerateBackupCodes(auth.getName()));
    }
}

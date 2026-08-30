package com.evidencevault.config;

import com.evidencevault.model.Role;
import com.evidencevault.model.User;
import com.evidencevault.repository.UserRepository;
import com.evidencevault.service.SignatureService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * CRITICAL: since AuthService.register() now always creates INVESTIGATOR accounts (see the
 * privilege-escalation fix - public self-registration can never grant ADMIN), there must be some
 * other way for the very first ADMIN to come into existence. This runner creates exactly one
 * admin account from environment variables, ONLY if no admin exists yet in the database.
 *
 * Required env vars (see .env.example): BOOTSTRAP_ADMIN_USERNAME, BOOTSTRAP_ADMIN_EMAIL,
 * BOOTSTRAP_ADMIN_PASSWORD. If any are unset, bootstrap is skipped with a warning log - the app
 * will still start, but nobody will be able to reach admin-only endpoints (audit chain, promote)
 * until an admin exists some other way (e.g. inserting one directly into the DB).
 *
 * Runs before DemoDataSeeder (@Order(1) vs (2)) since demo data references a real user.
 */
@Component
@Order(1)
@RequiredArgsConstructor
public class AdminBootstrapSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminBootstrapSeeder.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SignatureService signatureService;
    private final com.evidencevault.service.EncryptionService encryptionService;

    @Value("${evidencevault.bootstrap-admin.username:}")
    private String bootstrapUsername;

    @Value("${evidencevault.bootstrap-admin.email:}")
    private String bootstrapEmail;

    @Value("${evidencevault.bootstrap-admin.password:}")
    private String bootstrapPassword;

    @Override
    public void run(String... args) {
        boolean adminExists = userRepository.findAll().stream().anyMatch(u -> u.getRole() == Role.ADMIN);
        if (adminExists) {
            return; // already bootstrapped (or an admin was promoted manually) - nothing to do
        }

        if (isBlank(bootstrapUsername) || isBlank(bootstrapEmail) || isBlank(bootstrapPassword)) {
            log.warn("No ADMIN account exists and BOOTSTRAP_ADMIN_USERNAME/EMAIL/PASSWORD are not "
                    + "fully set - skipping admin bootstrap. Set these env vars and restart, or you "
                    + "will have no way to reach admin-only endpoints (audit chain, user promotion).");
            return;
        }

        if (userRepository.existsByUsername(bootstrapUsername)) {
            log.warn("BOOTSTRAP_ADMIN_USERNAME '{}' already exists as a non-admin user - not "
                    + "auto-promoting it. Use POST /api/auth/users/promote from an existing admin, "
                    + "or pick a different bootstrap username.", bootstrapUsername);
            return;
        }

        var keyPair = signatureService.generateKeyPair();
        User admin = User.builder()
                .username(bootstrapUsername)
                .email(bootstrapEmail)
                .password(passwordEncoder.encode(bootstrapPassword))
                .role(Role.ADMIN)
                .rsaPublicKey(keyPair.publicKeyBase64())
                .rsaPrivateKey(encryptionService.encryptStringWithMasterKey(keyPair.privateKeyBase64()))
                .build();
        userRepository.save(admin);

        log.info("Bootstrapped initial ADMIN account '{}'. Log in with this account, then either "
                + "use it directly or promote another INVESTIGATOR account and stop using this one.",
                bootstrapUsername);
    }

    private boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}

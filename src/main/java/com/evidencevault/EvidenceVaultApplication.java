package com.evidencevault;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling // needed for TokenBlacklistService's periodic cleanup of expired revocations
public class EvidenceVaultApplication {
    public static void main(String[] args) {
        SpringApplication.run(EvidenceVaultApplication.class, args);
    }
}

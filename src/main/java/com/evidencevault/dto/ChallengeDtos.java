package com.evidencevault.dto;

import jakarta.validation.constraints.NotBlank;

import java.util.UUID;

public class ChallengeDtos {

    public record ChallengeSummary(
            UUID id,
            String title,
            String category,
            String difficulty,
            int points,
            boolean solvedByMe,
            boolean hasArtifact
    ) {}

    public record ChallengeDetail(
            UUID id,
            String title,
            String description,
            String category,
            String difficulty,
            int points,
            boolean solvedByMe,
            boolean hasArtifact,
            String artifactFilename
    ) {}

    public record SubmitFlagRequest(
            @NotBlank String flag
    ) {}

    public record SubmitFlagResponse(
            boolean correct,
            boolean alreadySolved,
            int pointsAwarded,
            String message
    ) {}

    public record LeaderboardEntry(
            String username,
            int totalPoints,
            int challengesSolved
    ) {}

    public record MyProgress(
            int totalPoints,
            int challengesSolved,
            int totalChallenges
    ) {}
}

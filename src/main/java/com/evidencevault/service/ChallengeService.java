package com.evidencevault.service;

import com.evidencevault.dto.ChallengeDtos.*;
import com.evidencevault.dto.EvidenceDtos.FileTypeResponse;
import com.evidencevault.dto.EvidenceDtos.HexDumpResponse;
import com.evidencevault.dto.EvidenceDtos.StringsResponse;
import com.evidencevault.model.Challenge;
import com.evidencevault.model.ChallengeSubmission;
import com.evidencevault.repository.ChallengeRepository;
import com.evidencevault.repository.ChallengeSubmissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ChallengeService {

    private final ChallengeRepository challengeRepository;
    private final ChallengeSubmissionRepository submissionRepository;
    private final HashService hashService;
    private final ForensicAnalysisService forensicAnalysisService;

    public List<ChallengeSummary> listChallenges(String username) {
        return challengeRepository.findAll().stream()
                .sorted(Comparator.comparing(Challenge::getPoints))
                .map(c -> new ChallengeSummary(
                        c.getId(), c.getTitle(), c.getCategory().name(), c.getDifficulty().name(),
                        c.getPoints(), isSolvedBy(c.getId(), username), c.getArtifactBase64() != null))
                .toList();
    }

    public ChallengeDetail getChallenge(String username, UUID id) {
        Challenge c = getOrThrow(id);
        return new ChallengeDetail(c.getId(), c.getTitle(), c.getDescription(), c.getCategory().name(),
                c.getDifficulty().name(), c.getPoints(), isSolvedBy(id, username),
                c.getArtifactBase64() != null, c.getArtifactFilename());
    }

    public byte[] getArtifactBytes(UUID id) {
        Challenge c = getOrThrow(id);
        if (c.getArtifactBase64() == null) {
            throw new IllegalArgumentException("This challenge has no downloadable artifact");
        }
        return Base64.getDecoder().decode(c.getArtifactBase64());
    }

    public String getArtifactFilename(UUID id) {
        return getOrThrow(id).getArtifactFilename();
    }

    public FileTypeResponse analyzeFileType(UUID id) {
        Challenge c = getOrThrow(id);
        byte[] data = getArtifactBytes(id);
        var r = forensicAnalysisService.detectFileType(data, c.getArtifactFilename(), "application/octet-stream");
        return new FileTypeResponse(r.detectedType(), "application/octet-stream", r.claimedExtension(), r.mismatch(), r.signatureHex());
    }

    public HexDumpResponse hexDump(UUID id) {
        byte[] data = getArtifactBytes(id);
        int maxBytes = 512;
        List<String> lines = forensicAnalysisService.hexDump(data, maxBytes);
        return new HexDumpResponse(lines, Math.min(data.length, maxBytes), data.length);
    }

    public StringsResponse extractStrings(UUID id) {
        byte[] data = getArtifactBytes(id);
        var r = forensicAnalysisService.extractStrings(data, 4, 200);
        return new StringsResponse(r.strings(), r.totalFound(), r.truncated());
    }

    @Transactional
    public SubmitFlagResponse submitFlag(String username, UUID id, String flagText) {
        Challenge c = getOrThrow(id);
        String submittedHash = hashService.sha256Hex(flagText.trim());
        boolean correct = submittedHash.equals(c.getFlagHash());

        boolean alreadySolved = isSolvedBy(id, username);

        ChallengeSubmission submission = ChallengeSubmission.builder()
                .challenge(c)
                .username(username)
                .correct(correct)
                .build();
        submissionRepository.save(submission);

        if (correct && !alreadySolved) {
            return new SubmitFlagResponse(true, false, c.getPoints(),
                    "Correct! +" + c.getPoints() + " points.");
        } else if (correct) {
            return new SubmitFlagResponse(true, true, 0,
                    "Correct, but you already solved this one - no additional points awarded.");
        } else {
            return new SubmitFlagResponse(false, false, 0, "Incorrect flag. Try again.");
        }
    }

    public List<LeaderboardEntry> leaderboard() {
        List<ChallengeSubmission> correctSubmissions = submissionRepository.findByCorrectTrue();

        // one point-award per (username, challenge) pair - first correct submission counts
        Map<String, List<ChallengeSubmission>> byUser = correctSubmissions.stream()
                .collect(Collectors.groupingBy(ChallengeSubmission::getUsername));

        return byUser.entrySet().stream()
                .map(entry -> {
                    List<UUID> distinctChallenges = entry.getValue().stream()
                            .map(s -> s.getChallenge().getId())
                            .distinct()
                            .toList();
                    int totalPoints = distinctChallenges.stream()
                            .mapToInt(cid -> challengeRepository.findById(cid).map(Challenge::getPoints).orElse(0))
                            .sum();
                    return new LeaderboardEntry(entry.getKey(), totalPoints, distinctChallenges.size());
                })
                .sorted(Comparator.comparingInt(LeaderboardEntry::totalPoints).reversed())
                .toList();
    }

    public MyProgress myProgress(String username) {
        List<UUID> solved = submissionRepository.findByUsernameAndCorrectTrue(username).stream()
                .map(s -> s.getChallenge().getId())
                .distinct()
                .toList();
        int totalPoints = solved.stream()
                .mapToInt(cid -> challengeRepository.findById(cid).map(Challenge::getPoints).orElse(0))
                .sum();
        return new MyProgress(totalPoints, solved.size(), (int) challengeRepository.count());
    }

    private boolean isSolvedBy(UUID challengeId, String username) {
        return submissionRepository.existsByChallengeIdAndUsernameAndCorrectTrue(challengeId, username);
    }

    private Challenge getOrThrow(UUID id) {
        return challengeRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Challenge not found"));
    }
}

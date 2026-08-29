package com.evidencevault.controller;

import com.evidencevault.dto.ChallengeDtos.*;
import com.evidencevault.dto.EvidenceDtos.FileTypeResponse;
import com.evidencevault.dto.EvidenceDtos.HexDumpResponse;
import com.evidencevault.dto.EvidenceDtos.StringsResponse;
import com.evidencevault.service.ChallengeService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/challenges")
@RequiredArgsConstructor
public class ChallengeController {

    private final ChallengeService challengeService;

    @GetMapping
    public ResponseEntity<List<ChallengeSummary>> list(Authentication auth) {
        return ResponseEntity.ok(challengeService.listChallenges(auth.getName()));
    }

    @GetMapping("/leaderboard")
    public ResponseEntity<List<LeaderboardEntry>> leaderboard() {
        return ResponseEntity.ok(challengeService.leaderboard());
    }

    @GetMapping("/my-progress")
    public ResponseEntity<MyProgress> myProgress(Authentication auth) {
        return ResponseEntity.ok(challengeService.myProgress(auth.getName()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ChallengeDetail> get(Authentication auth, @PathVariable UUID id) {
        return ResponseEntity.ok(challengeService.getChallenge(auth.getName(), id));
    }

    @GetMapping("/{id}/artifact")
    public ResponseEntity<ByteArrayResource> artifact(@PathVariable UUID id) {
        byte[] data = challengeService.getArtifactBytes(id);
        String filename = challengeService.getArtifactFilename(id);
        ContentDisposition disposition = ContentDisposition.attachment().filename(filename).build();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                .header(HttpHeaders.CONTENT_TYPE, "application/octet-stream")
                .body(new ByteArrayResource(data));
    }

    @GetMapping("/{id}/analysis/file-type")
    public ResponseEntity<FileTypeResponse> fileType(@PathVariable UUID id) {
        return ResponseEntity.ok(challengeService.analyzeFileType(id));
    }

    @GetMapping("/{id}/analysis/hexdump")
    public ResponseEntity<HexDumpResponse> hexDump(@PathVariable UUID id) {
        return ResponseEntity.ok(challengeService.hexDump(id));
    }

    @GetMapping("/{id}/analysis/strings")
    public ResponseEntity<StringsResponse> strings(@PathVariable UUID id) {
        return ResponseEntity.ok(challengeService.extractStrings(id));
    }

    @PostMapping("/{id}/submit")
    public ResponseEntity<SubmitFlagResponse> submit(Authentication auth, @PathVariable UUID id,
                                                       @Valid @RequestBody SubmitFlagRequest request) {
        return ResponseEntity.ok(challengeService.submitFlag(auth.getName(), id, request.flag()));
    }
}

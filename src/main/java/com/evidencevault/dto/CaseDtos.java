package com.evidencevault.dto;

import jakarta.validation.constraints.NotBlank;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public class CaseDtos {

    public record CreateCaseRequest(
            @NotBlank String caseNumber,
            @NotBlank String title,
            String description
    ) {}

    public record UpdateStatusRequest(
            @NotBlank String status // OPEN, CLOSED, ARCHIVED
    ) {}

    public record AssignInvestigatorRequest(
            @NotBlank String username
    ) {}

    public record CaseResponse(
            UUID id,
            String caseNumber,
            String title,
            String description,
            String status,
            String createdBy,
            Instant createdAt,
            List<String> assignedInvestigators
    ) {}
}

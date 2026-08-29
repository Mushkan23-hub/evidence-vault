package com.evidencevault.dto;

import java.time.Instant;

public class TimelineDtos {
    public record TimelineEvent(
            String action,
            String actorUsername,
            String details,
            Instant timestamp
    ) {}
}

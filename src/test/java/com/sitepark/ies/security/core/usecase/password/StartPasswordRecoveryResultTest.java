package com.sitepark.ies.security.core.usecase.password;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class StartPasswordRecoveryResultTest {

  @Test
  void testChallengeIdIsStored() {

    StartPasswordRecoveryResult result =
        new StartPasswordRecoveryResult(
            "challenge-123",
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"));

    assertEquals(
        "challenge-123", result.challengeId(), "ChallengeId should match the provided value");
  }

  @Test
  void testCreatedAtIsStored() {

    Instant createdAt = Instant.parse("2025-01-01T10:00:00Z");
    StartPasswordRecoveryResult result =
        new StartPasswordRecoveryResult(
            "challenge-123", createdAt, Instant.parse("2025-01-01T10:15:00Z"));

    assertEquals(createdAt, result.createdAt(), "CreatedAt should match the provided value");
  }

  @Test
  void testExpiresAtIsStored() {

    Instant expiresAt = Instant.parse("2025-01-01T10:15:00Z");
    StartPasswordRecoveryResult result =
        new StartPasswordRecoveryResult(
            "challenge-123", Instant.parse("2025-01-01T10:00:00Z"), expiresAt);

    assertEquals(expiresAt, result.expiresAt(), "ExpiresAt should match the provided value");
  }
}

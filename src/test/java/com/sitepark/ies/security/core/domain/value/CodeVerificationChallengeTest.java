package com.sitepark.ies.security.core.domain.value;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

import com.sitepark.ies.sharedkernel.security.CodeVerificationChallenge;
import com.sitepark.ies.sharedkernel.security.CodeVerificationPayload;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class CodeVerificationChallengeTest {

  @Test
  void testIncrementAttempts() {

    CodeVerificationPayload payload = mock();
    Instant createdAt = mock();
    Instant expiresAt = mock();

    CodeVerificationChallenge challenge =
        new CodeVerificationChallenge("id", 123, payload, createdAt, expiresAt, 2);

    CodeVerificationChallenge updatedChallenge = challenge.incrementAttempts();

    CodeVerificationChallenge expected =
        new CodeVerificationChallenge("id", 123, payload, createdAt, expiresAt, 3);

    assertEquals(expected, updatedChallenge, "Expected updated challenge to match");
  }
}

package com.sitepark.ies.security.core.domain.value;

import java.time.Instant;

public record CodeVerificationChallenge(
    String challengeId,
    int code,
    CodeVerificationPayload payload,
    Instant createdAt,
    Instant expiresAt,
    int attempts) {

  public CodeVerificationChallenge incrementAttempts() {
    return new CodeVerificationChallenge(
        this.challengeId,
        this.code,
        this.payload,
        this.createdAt,
        this.expiresAt,
        this.attempts + 1);
  }
}

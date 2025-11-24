package com.sitepark.ies.security.core.usecase.password;

import java.time.Instant;

public record StartPasswordRecoveryResult(
    String challengeId, Instant createdAt, Instant expiresAt) {}

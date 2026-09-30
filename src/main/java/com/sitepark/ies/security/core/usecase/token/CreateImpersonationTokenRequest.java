package com.sitepark.ies.security.core.usecase.token;

import java.time.Instant;
import org.jspecify.annotations.Nullable;

public record CreateImpersonationTokenRequest(
    String userId, String name, @Nullable Instant expiresAt) {
  public CreateImpersonationTokenRequest {
    if (name == null || name.isBlank()) {
      throw new IllegalArgumentException("Name must not be null or blank");
    }
  }
}

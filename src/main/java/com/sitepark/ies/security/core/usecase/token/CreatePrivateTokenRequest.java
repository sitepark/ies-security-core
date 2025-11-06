package com.sitepark.ies.security.core.usecase.token;

import java.time.Instant;
import org.jetbrains.annotations.Nullable;

public record CreatePrivateTokenRequest(String name, @Nullable Instant expiresAt) {
  public CreatePrivateTokenRequest {
    if (name == null || name.isBlank()) {
      throw new IllegalArgumentException("Name must not be null or blank");
    }
  }
}

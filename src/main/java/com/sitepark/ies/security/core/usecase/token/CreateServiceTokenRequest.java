package com.sitepark.ies.security.core.usecase.token;

import com.sitepark.ies.sharedkernel.security.Permission;
import java.time.Instant;
import java.util.List;
import javax.annotation.concurrent.Immutable;
import org.jetbrains.annotations.Nullable;

@Immutable
public record CreateServiceTokenRequest(
    String name, List<Permission> permissions, @Nullable Instant expiresAt) {
  public CreateServiceTokenRequest {
    if (name == null || name.isBlank()) {
      throw new IllegalArgumentException("Name must not be null or blank");
    }
    permissions = List.copyOf(permissions);
  }

  public List<Permission> permissions() {
    return List.copyOf(permissions);
  }
}

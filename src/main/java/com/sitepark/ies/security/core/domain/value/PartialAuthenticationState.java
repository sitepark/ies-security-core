package com.sitepark.ies.security.core.domain.value;

import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.User;
import java.time.Instant;
import java.util.List;

public record PartialAuthenticationState(
    User user,
    AuthMethod method,
    List<AuthenticationRequirement> requirements,
    Instant createdAt,
    String purpose) {

  private static final List<AuthenticationRequirement> EMPTY_REQUIREMENTS = List.of();

  public PartialAuthenticationState {
    requirements =
        requirements != null
            ? List.copyOf(requirements) // Immutable defensive copy
            : EMPTY_REQUIREMENTS;
  }
}

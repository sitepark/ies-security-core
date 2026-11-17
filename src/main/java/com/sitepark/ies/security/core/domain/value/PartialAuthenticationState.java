package com.sitepark.ies.security.core.domain.value;

import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.User;
import java.time.Instant;
import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * A login that waits for a second factor.
 *
 * @param emailCodeChallengeId the code verification challenge whose code was sent by e-mail, if
 *     the login waits for an e-mail code
 */
public record PartialAuthenticationState(
    User user,
    AuthMethod method,
    List<AuthenticationRequirement> requirements,
    Instant createdAt,
    String purpose,
    @Nullable String emailCodeChallengeId) {

  private static final List<AuthenticationRequirement> EMPTY_REQUIREMENTS = List.of();

  public PartialAuthenticationState {
    requirements =
        requirements != null
            ? List.copyOf(requirements) // Immutable defensive copy
            : EMPTY_REQUIREMENTS;
  }

  public PartialAuthenticationState(
      User user,
      AuthMethod method,
      List<AuthenticationRequirement> requirements,
      Instant createdAt,
      String purpose) {
    this(user, method, requirements, createdAt, purpose, null);
  }
}

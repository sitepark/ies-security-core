package com.sitepark.ies.security.core.domain.value;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * The login requirement of a user. Until the deadline the user is reminded at every login and may
 * still log in without meeting the requirement; afterwards the requirement is enforced. A policy
 * without a deadline is enforced at once.
 */
public record AuthenticationPolicy(AuthenticationPolicyLevel level, @Nullable Instant deadline) {

  public static final AuthenticationPolicy NONE =
      new AuthenticationPolicy(AuthenticationPolicyLevel.NONE, null);

  public AuthenticationPolicy {
    Objects.requireNonNull(level, "level cannot be null");
  }

  /** Returns whether the requirement is enforced at the given time. */
  public boolean isEnforced(Instant now) {
    if (this.level == AuthenticationPolicyLevel.NONE) {
      return false;
    }
    return this.deadline == null || !now.isBefore(this.deadline);
  }
}

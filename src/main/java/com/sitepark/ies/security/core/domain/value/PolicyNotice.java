package com.sitepark.ies.security.core.domain.value;

import java.time.Instant;
import java.util.Objects;

/** Reminds a user at login that a requirement will be enforced from the deadline on. */
public record PolicyNotice(AuthenticationPolicyLevel level, Instant deadline) {

  public PolicyNotice {
    Objects.requireNonNull(level, "level cannot be null");
    Objects.requireNonNull(deadline, "deadline cannot be null");
  }
}

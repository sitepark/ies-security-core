package com.sitepark.ies.security.core.domain.value;

import java.util.Objects;
import org.jspecify.annotations.Nullable;

/** Whether a login way is allowed for a user under the user's authentication policy. */
public sealed interface PolicyDecision {

  /** The login may go on, possibly with a reminder for the user. */
  record Allowed(@Nullable PolicyNotice notice) implements PolicyDecision {}

  /** The login is refused. */
  record Denied(AuthenticationFailureReason reason) implements PolicyDecision {
    public Denied {
      Objects.requireNonNull(reason, "reason cannot be null");
    }
  }
}

package com.sitepark.ies.security.core.domain.value;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class AuthenticationPolicyTest {

  private static final Instant NOW = Instant.parse("2026-11-16T10:00:00Z");

  @Test
  void testNoneIsNeverEnforced() {
    assertFalse(AuthenticationPolicy.NONE.isEnforced(NOW), "NONE must never be enforced");
  }

  @Test
  void testWithoutDeadlineEnforcedAtOnce() {
    AuthenticationPolicy policy =
        new AuthenticationPolicy(AuthenticationPolicyLevel.SECOND_FACTOR, null);
    assertTrue(policy.isEnforced(NOW), "a policy without deadline must be enforced at once");
  }

  @Test
  void testNotEnforcedBeforeDeadline() {
    AuthenticationPolicy policy =
        new AuthenticationPolicy(AuthenticationPolicyLevel.PASSKEY, NOW.plusSeconds(1));
    assertFalse(policy.isEnforced(NOW), "a policy must not be enforced before its deadline");
  }

  @Test
  void testEnforcedAtDeadline() {
    AuthenticationPolicy policy = new AuthenticationPolicy(AuthenticationPolicyLevel.PASSKEY, NOW);
    assertTrue(policy.isEnforced(NOW), "a policy must be enforced from its deadline on");
  }
}

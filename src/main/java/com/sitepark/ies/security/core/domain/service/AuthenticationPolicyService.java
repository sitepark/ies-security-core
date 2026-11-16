package com.sitepark.ies.security.core.domain.service;

import com.sitepark.ies.security.core.domain.value.AuthenticationFailureReason;
import com.sitepark.ies.security.core.domain.value.AuthenticationPolicy;
import com.sitepark.ies.security.core.domain.value.AuthenticationPolicyLevel;
import com.sitepark.ies.security.core.domain.value.PolicyDecision;
import com.sitepark.ies.security.core.domain.value.PolicyNotice;
import com.sitepark.ies.security.core.port.AuthenticationPolicyRepository;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

/**
 * Decides whether a login way that does not use a passkey is allowed under the authentication
 * policy of a user. A login with a passkey meets every policy and needs no decision.
 *
 * <ul>
 *   <li>{@code SECOND_FACTOR}: a password login of a user with a TOTP secret goes on to the TOTP
 *       step. Any other way is allowed until the deadline and refused afterwards.
 *   <li>{@code PASSKEY}: every way except the passkey is allowed until the deadline and refused
 *       afterwards, even with a TOTP secret.
 * </ul>
 */
public class AuthenticationPolicyService {

  private final AuthenticationPolicyRepository repository;

  private final Clock clock;

  @Inject
  protected AuthenticationPolicyService(AuthenticationPolicyRepository repository, Clock clock) {
    this.repository = repository;
    this.clock = clock;
  }

  public AuthenticationPolicy getPolicy(String userId) {
    return this.repository.get(userId).orElse(AuthenticationPolicy.NONE);
  }

  /**
   * Decides about a login with the password.
   *
   * @param user the user whose password has been checked
   * @param secondFactorFollows whether the login is completed with a second factor of the user
   */
  public PolicyDecision decidePasswordLogin(User user, boolean secondFactorFollows) {
    return this.decide(user, secondFactorFollows);
  }

  /** Decides about a login through an external identity provider, which has no second factor. */
  public PolicyDecision decideExternalLogin(User user) {
    return this.decide(user, false);
  }

  /** Returns whether the user may get a new password through the password recovery. */
  public boolean isPasswordRecoveryAllowed(User user) {
    AuthenticationPolicy policy = this.getPolicy(user.id());
    return policy.level() != AuthenticationPolicyLevel.PASSKEY
        || !policy.isEnforced(Instant.now(this.clock));
  }

  private PolicyDecision decide(User user, boolean secondFactorFollows) {
    AuthenticationPolicy policy = this.getPolicy(user.id());
    Instant now = Instant.now(this.clock);
    return switch (policy.level()) {
      case NONE -> new PolicyDecision.Allowed(null);
      case SECOND_FACTOR -> {
        if (secondFactorFollows) {
          yield new PolicyDecision.Allowed(null);
        }
        yield policy.isEnforced(now)
            ? new PolicyDecision.Denied(AuthenticationFailureReason.SECOND_FACTOR_REQUIRED)
            : new PolicyDecision.Allowed(notice(policy));
      }
      case PASSKEY ->
          policy.isEnforced(now)
              ? new PolicyDecision.Denied(AuthenticationFailureReason.PASSKEY_REQUIRED)
              : new PolicyDecision.Allowed(notice(policy));
    };
  }

  private static PolicyNotice notice(AuthenticationPolicy policy) {
    return new PolicyNotice(
        policy.level(),
        Objects.requireNonNull(policy.deadline(), "a policy that is not enforced has a deadline"));
  }
}

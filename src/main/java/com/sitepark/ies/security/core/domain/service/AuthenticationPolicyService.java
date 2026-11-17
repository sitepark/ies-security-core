package com.sitepark.ies.security.core.domain.service;

import com.sitepark.ies.security.core.domain.exception.AuthFactorNotAllowedException;
import com.sitepark.ies.security.core.domain.exception.AuthenticationPolicyNotAllowedException;
import com.sitepark.ies.security.core.domain.value.AuthFactorType;
import com.sitepark.ies.security.core.domain.value.AuthenticationFailureReason;
import com.sitepark.ies.security.core.domain.value.AuthenticationPolicy;
import com.sitepark.ies.security.core.domain.value.AuthenticationPolicyLevel;
import com.sitepark.ies.security.core.domain.value.PolicyDecision;
import com.sitepark.ies.security.core.domain.value.PolicyNotice;
import com.sitepark.ies.security.core.domain.value.SystemAuthenticationSettings;
import com.sitepark.ies.security.core.port.AuthenticationPolicyRepository;
import com.sitepark.ies.security.core.port.SystemAuthenticationSettingsProvider;
import com.sitepark.ies.sharedkernel.security.AuthFactor;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

/**
 * Decides whether a login way that does not use a passkey is allowed under the authentication
 * policy of a user. A login with a passkey meets every policy and needs no decision.
 *
 * <p>The policy that applies is the stricter of the policy of the user and the minimum policy of the
 * installation ({@link SystemAuthenticationSettings}). Only factors the installation allows count.
 *
 * <ul>
 *   <li>{@code SECOND_FACTOR}: a password login of a user with an allowed second factor goes on to
 *       that step. Any other way is allowed until the deadline and refused afterwards.
 *   <li>{@code PASSKEY}: every way except the passkey is allowed until the deadline and refused
 *       afterwards, even with a second factor.
 * </ul>
 */
public class AuthenticationPolicyService {

  private final AuthenticationPolicyRepository repository;

  private final SystemAuthenticationSettingsProvider settingsProvider;

  private final Clock clock;

  @Inject
  protected AuthenticationPolicyService(
      AuthenticationPolicyRepository repository,
      SystemAuthenticationSettingsProvider settingsProvider,
      Clock clock) {
    this.repository = repository;
    this.settingsProvider = settingsProvider;
    this.clock = clock;
  }

  /** Returns the policy set for the user, without the minimum policy of the installation. */
  public AuthenticationPolicy getPolicy(String userId) {
    return this.repository.get(userId).orElse(AuthenticationPolicy.NONE);
  }

  /** Returns the policy that applies to the user: the stricter of user and installation policy. */
  public AuthenticationPolicy getEffectivePolicy(String userId) {
    return stricter(this.getPolicy(userId), this.settingsProvider.get().minimumPolicy());
  }

  public SystemAuthenticationSettings getSettings() {
    return this.settingsProvider.get();
  }

  public boolean isFactorAllowed(AuthFactorType factor) {
    return this.settingsProvider.get().isAllowed(factor);
  }

  /** Throws if the installation has switched the factor off. */
  public void requireFactorAllowed(AuthFactorType factor) {
    if (!this.isFactorAllowed(factor)) {
      throw new AuthFactorNotAllowedException(factor);
    }
  }

  /** Throws if the policy cannot be met with the factors the installation allows. */
  public void requirePolicyAllowed(AuthenticationPolicy policy) {
    if (!this.settingsProvider.get().canMeet(policy.level())) {
      throw new AuthenticationPolicyNotAllowedException(policy.level());
    }
  }

  /** Returns whether a password login of the user goes on to a second factor step. */
  public boolean hasAllowedSecondFactor(User user) {
    return user.authFactors().contains(AuthFactor.TOTP)
        && this.isFactorAllowed(AuthFactorType.TOTP);
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
    AuthenticationPolicy policy = this.getEffectivePolicy(user.id());
    return policy.level() != AuthenticationPolicyLevel.PASSKEY
        || !policy.isEnforced(Instant.now(this.clock));
  }

  private PolicyDecision decide(User user, boolean secondFactorFollows) {
    AuthenticationPolicy policy = this.getEffectivePolicy(user.id());
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

  /**
   * Returns the stricter policy: the higher level wins; with the same level the one that is enforced
   * earlier (no deadline means enforced at once).
   */
  static AuthenticationPolicy stricter(AuthenticationPolicy a, AuthenticationPolicy b) {
    int compare = a.level().compareTo(b.level());
    if (compare != 0) {
      return compare > 0 ? a : b;
    }
    if (a.deadline() == null) {
      return a;
    }
    if (b.deadline() == null) {
      return b;
    }
    return a.deadline().isBefore(b.deadline()) ? a : b;
  }

  private static PolicyNotice notice(AuthenticationPolicy policy) {
    return new PolicyNotice(
        policy.level(),
        Objects.requireNonNull(policy.deadline(), "a policy that is not enforced has a deadline"));
  }
}

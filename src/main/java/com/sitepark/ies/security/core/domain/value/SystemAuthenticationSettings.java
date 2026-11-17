package com.sitepark.ies.security.core.domain.value;

import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * The login settings of an installation: which second factors exist at all and which requirement
 * applies to every user. The password is always a login method; "password alone is not enough" is
 * the minimum policy {@code SECOND_FACTOR}.
 */
public record SystemAuthenticationSettings(
    Set<AuthFactorType> allowedFactors, AuthenticationPolicy minimumPolicy) {

  /** The behaviour without settings: TOTP and passkeys, no e-mail code, no minimum requirement. */
  public static final SystemAuthenticationSettings DEFAULT =
      new SystemAuthenticationSettings(
          EnumSet.of(AuthFactorType.TOTP, AuthFactorType.PASSKEY), AuthenticationPolicy.NONE);

  public SystemAuthenticationSettings {
    Objects.requireNonNull(allowedFactors, "allowedFactors cannot be null");
    Objects.requireNonNull(minimumPolicy, "minimumPolicy cannot be null");
    allowedFactors =
        allowedFactors.isEmpty() ? Set.of() : Set.copyOf(EnumSet.copyOf(allowedFactors));
  }

  public boolean isAllowed(AuthFactorType factor) {
    return this.allowedFactors.contains(factor);
  }

  /** Returns whether the level can be met with the allowed factors. */
  public boolean canMeet(AuthenticationPolicyLevel level) {
    return switch (level) {
      case NONE -> true;
      // a passkey login meets the second factor requirement as well
      case SECOND_FACTOR -> !this.allowedFactors.isEmpty();
      case PASSKEY -> this.isAllowed(AuthFactorType.PASSKEY);
    };
  }

  /** Returns whether the minimum policy can be met with the allowed factors. */
  public boolean isValid() {
    return this.canMeet(this.minimumPolicy.level());
  }
}

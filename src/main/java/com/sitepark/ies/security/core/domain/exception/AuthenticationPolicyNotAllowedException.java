package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.security.core.domain.value.AuthenticationPolicyLevel;
import com.sitepark.ies.sharedkernel.domain.DomainException;
import java.io.Serial;

/** Thrown when a policy is set that cannot be met with the factors the installation allows. */
public class AuthenticationPolicyNotAllowedException extends DomainException {

  @Serial private static final long serialVersionUID = 1L;

  private final AuthenticationPolicyLevel level;

  public AuthenticationPolicyNotAllowedException(AuthenticationPolicyLevel level) {
    super("The policy " + level + " cannot be met with the factors allowed on this installation");
    this.level = level;
  }

  public AuthenticationPolicyLevel getLevel() {
    return this.level;
  }
}

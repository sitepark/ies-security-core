package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.security.core.domain.value.AuthFactorType;
import com.sitepark.ies.sharedkernel.domain.DomainException;
import java.io.Serial;

/** Thrown when a second factor is used or set up that the installation has switched off. */
public class AuthFactorNotAllowedException extends DomainException {

  @Serial private static final long serialVersionUID = 1L;

  private final AuthFactorType factor;

  public AuthFactorNotAllowedException(AuthFactorType factor) {
    super("The factor " + factor + " is not allowed on this installation");
    this.factor = factor;
  }

  public AuthFactorType getFactor() {
    return this.factor;
  }
}

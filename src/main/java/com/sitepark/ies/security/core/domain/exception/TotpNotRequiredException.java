package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.sharedkernel.domain.DomainException;
import java.io.Serial;

/** Thrown when TOTP validation is requested for an authentication process that does not require it. */
public class TotpNotRequiredException extends DomainException {

  @Serial private static final long serialVersionUID = 1L;

  public TotpNotRequiredException() {
    super("TOTP code validation is not required for this authentication process");
  }
}

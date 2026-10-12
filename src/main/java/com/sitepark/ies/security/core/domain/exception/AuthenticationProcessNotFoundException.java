package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.sharedkernel.domain.DomainException;
import java.io.Serial;

/** Thrown when an authentication process does not exist or has expired. */
public class AuthenticationProcessNotFoundException extends DomainException {

  @Serial private static final long serialVersionUID = 1L;

  public AuthenticationProcessNotFoundException() {
    super("Authentication process not found or expired");
  }
}

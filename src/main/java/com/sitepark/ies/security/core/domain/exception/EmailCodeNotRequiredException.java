package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.sharedkernel.domain.DomainException;
import java.io.Serial;

/** Thrown when an e-mail code is sent for a login process that does not wait for one. */
public class EmailCodeNotRequiredException extends DomainException {

  @Serial private static final long serialVersionUID = 1L;

  public EmailCodeNotRequiredException() {
    super("An e-mail code is not required for this authentication process");
  }
}

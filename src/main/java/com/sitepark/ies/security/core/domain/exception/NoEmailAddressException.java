package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.sharedkernel.domain.DomainException;
import java.io.Serial;

/** Thrown when the e-mail code is set up for a user without an e-mail address. */
public class NoEmailAddressException extends DomainException {

  @Serial private static final long serialVersionUID = 1L;

  public NoEmailAddressException(String userId) {
    super("The user " + userId + " has no e-mail address");
  }
}

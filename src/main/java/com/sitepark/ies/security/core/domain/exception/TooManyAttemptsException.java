package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.sharedkernel.security.Authentication;
import java.io.Serial;

public class TooManyAttemptsException extends AuthenticationFailedException {

  @Serial private static final long serialVersionUID = 1L;

  public TooManyAttemptsException(Authentication authentication) {
    super(authentication, "Too many failed login attempts");
  }
}

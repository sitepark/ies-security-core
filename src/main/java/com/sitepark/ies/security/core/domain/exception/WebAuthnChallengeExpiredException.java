package com.sitepark.ies.security.core.domain.exception;

import java.io.Serial;

/** Thrown when the WebAuthn challenge is missing or has expired. */
public class WebAuthnChallengeExpiredException extends WebAuthnException {

  @Serial private static final long serialVersionUID = 1L;

  public WebAuthnChallengeExpiredException(String msg) {
    super(msg);
  }

  public WebAuthnChallengeExpiredException(String msg, Throwable cause) {
    super(msg, cause);
  }
}

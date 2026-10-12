package com.sitepark.ies.security.core.domain.exception;

import java.io.Serial;

/** Thrown when the verification of a WebAuthn registration or assertion failed. */
public class WebAuthnVerificationFailedException extends WebAuthnException {

  @Serial private static final long serialVersionUID = 1L;

  public WebAuthnVerificationFailedException(String msg) {
    super(msg);
  }

  public WebAuthnVerificationFailedException(String msg, Throwable cause) {
    super(msg, cause);
  }
}

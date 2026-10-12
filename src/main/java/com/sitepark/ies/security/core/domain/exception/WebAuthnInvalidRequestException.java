package com.sitepark.ies.security.core.domain.exception;

import java.io.Serial;

/** Thrown when the WebAuthn credential or assertion JSON cannot be parsed. */
public class WebAuthnInvalidRequestException extends WebAuthnException {

  @Serial private static final long serialVersionUID = 1L;

  public WebAuthnInvalidRequestException(String msg) {
    super(msg);
  }

  public WebAuthnInvalidRequestException(String msg, Throwable cause) {
    super(msg, cause);
  }
}

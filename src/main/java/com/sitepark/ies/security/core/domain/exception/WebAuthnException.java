package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.sharedkernel.domain.DomainException;
import java.io.Serial;

public class WebAuthnException extends DomainException {
  @Serial private static final long serialVersionUID = 1L;

  public WebAuthnException(String msg) {
    super(msg);
  }

  public WebAuthnException(String msg, Throwable cause) {
    super(msg, cause);
  }
}

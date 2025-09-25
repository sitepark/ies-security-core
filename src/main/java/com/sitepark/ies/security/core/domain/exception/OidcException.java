package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.sharedkernel.domain.DomainException;
import java.io.Serial;

public class OidcException extends DomainException {
  @Serial private static final long serialVersionUID = 1L;

  public OidcException(String msg) {
    super(msg);
  }

  public OidcException(String msg, Throwable cause) {
    super(msg, cause);
  }
}

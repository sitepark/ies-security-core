package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.sharedkernel.domain.DomainException;
import java.io.Serial;

public class CodeVerificationFailedException extends DomainException {
  @Serial private static final long serialVersionUID = 1L;

  public CodeVerificationFailedException(String message) {
    super(message);
  }

  public CodeVerificationFailedException(String message, Throwable cause) {
    super(message, cause);
  }
}

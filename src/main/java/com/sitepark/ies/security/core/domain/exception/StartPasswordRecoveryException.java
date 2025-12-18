package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.sharedkernel.domain.DomainException;
import java.io.Serial;

public class StartPasswordRecoveryException extends DomainException {
  @Serial private static final long serialVersionUID = 1L;

  public StartPasswordRecoveryException(String msg) {
    super(msg);
  }

  public StartPasswordRecoveryException(String msg, Throwable cause) {
    super(msg, cause);
  }
}

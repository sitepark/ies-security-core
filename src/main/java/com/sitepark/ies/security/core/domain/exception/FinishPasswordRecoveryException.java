package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.sharedkernel.domain.DomainException;
import java.io.Serial;

public class FinishPasswordRecoveryException extends DomainException {
  @Serial private static final long serialVersionUID = 1L;

  public FinishPasswordRecoveryException(String msg) {
    super(msg);
  }

  public FinishPasswordRecoveryException(String msg, Throwable cause) {
    super(msg, cause);
  }
}

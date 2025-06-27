package com.sitepark.ies.security.core.domain.exception;

import java.io.Serial;

public class VaultException extends RuntimeException {

  @Serial private static final long serialVersionUID = 1L;

  public VaultException(String msg) {
    super(msg);
  }

  public VaultException(String msg, Throwable cause) {
    super(msg, cause);
  }
}

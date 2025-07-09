package com.sitepark.ies.security.core.domain.exception;

import java.io.Serial;

public class OAuth2Exception extends RuntimeException {
  @Serial private static final long serialVersionUID = 1L;

  public OAuth2Exception(String msg) {
    super(msg);
  }

  public OAuth2Exception(String msg, Throwable cause) {
    super(msg, cause);
  }
}

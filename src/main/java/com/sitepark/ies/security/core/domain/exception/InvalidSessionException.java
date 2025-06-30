package com.sitepark.ies.security.core.domain.exception;

import java.io.Serial;

public class InvalidSessionException extends RuntimeException {

  @Serial private static final long serialVersionUID = 1L;

  private final String session;

  public InvalidSessionException(String session) {
    this(session, null);
  }

  public InvalidSessionException(String session, Throwable t) {
    super("Invalid session " + session, t);
    this.session = session;
  }

  public String getSession() {
    return this.session;
  }
}

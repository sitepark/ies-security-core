package com.sitepark.ies.security.core.domain.exception;

import java.io.Serial;

public class InvalidSessionException extends RuntimeException {

  @Serial private static final long serialVersionUID = 1L;

  private final long session;

  public InvalidSessionException(long session) {
    this(session, null);
  }

  public InvalidSessionException(long session, Throwable t) {
    super("Invalid session " + session, t);
    this.session = session;
  }

  public long getSession() {
    return this.session;
  }
}

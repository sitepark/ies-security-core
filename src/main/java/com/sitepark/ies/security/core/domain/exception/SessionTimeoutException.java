package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.sharedkernel.domain.DomainException;
import java.io.Serial;

public class SessionTimeoutException extends DomainException {

  @Serial private static final long serialVersionUID = 1L;

  private final long session;

  public SessionTimeoutException(long session) {
    super("Session timeout " + session);
    this.session = session;
  }

  public long getSession() {
    return this.session;
  }
}

package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.sharedkernel.domain.DomainException;
import java.io.Serial;
import org.jspecify.annotations.Nullable;

public class InvalidSessionException extends DomainException {

  @Serial private static final long serialVersionUID = 1L;

  private final String session;

  public InvalidSessionException(String session) {
    this(session, null);
  }

  public InvalidSessionException(String session, @Nullable Throwable t) {
    super("Invalid session " + session, t);
    this.session = session;
  }

  public String getSession() {
    return this.session;
  }
}

package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.sharedkernel.security.Authentication;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.Serial;

public class AuthenticationFailedException extends RuntimeException {

  @Serial private static final long serialVersionUID = 1L;

  private final transient Authentication authentication;

  public AuthenticationFailedException(Authentication authentication) {
    this(authentication, (Throwable) null);
  }

  @SuppressFBWarnings("EI_EXPOSE_REP2") // TODO
  public AuthenticationFailedException(Authentication authentication, String msg) {
    super(msg);
    this.authentication = authentication;
  }

  @SuppressFBWarnings("EI_EXPOSE_REP2") // TODO
  public AuthenticationFailedException(Authentication authentication, Throwable t) {
    super("Authentication failed: " + authentication.getName(), t);
    this.authentication = authentication;
  }

  @SuppressFBWarnings("EI_EXPOSE_REP2") // TODO
  public AuthenticationFailedException(Authentication authentication, String msg, Throwable t) {
    super(msg, t);
    this.authentication = authentication;
  }

  @SuppressFBWarnings("EI_EXPOSE_REP") // TODO
  public Authentication getAuthentication() {
    return this.authentication;
  }
}

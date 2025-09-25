package com.sitepark.ies.security.core.domain.exception;

import com.sitepark.ies.sharedkernel.domain.DomainException;
import com.sitepark.ies.sharedkernel.security.Authentication;
import java.io.Serial;

public class AuthenticationFailedException extends DomainException {

  @Serial private static final long serialVersionUID = 1L;

  private final transient Authentication authentication;

  public AuthenticationFailedException() {
    super();
    this.authentication = null;
  }

  public AuthenticationFailedException(String msg) {
    super(msg);
    this.authentication = null;
  }

  public AuthenticationFailedException(Authentication authentication) {
    this(authentication, (Throwable) null);
  }

  public AuthenticationFailedException(Authentication authentication, String msg) {
    super(msg);
    this.authentication = authentication;
  }

  public AuthenticationFailedException(Authentication authentication, Throwable t) {
    super("Authentication failed: " + authentication.name(), t);
    this.authentication = authentication;
  }

  public AuthenticationFailedException(Authentication authentication, String msg, Throwable t) {
    super(msg, t);
    this.authentication = authentication;
  }

  public Authentication getAuthentication() {
    return this.authentication;
  }
}

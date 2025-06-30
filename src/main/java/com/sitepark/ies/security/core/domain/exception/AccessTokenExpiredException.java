package com.sitepark.ies.security.core.domain.exception;

import java.time.Instant;

/**
 * The <code>AccessTokenExpiredException</code> exception is thrown when an access token has expired
 * and is no longer valid for authentication purposes.
 */
public class AccessTokenExpiredException extends AuthenticationFailedException {

  private static final long serialVersionUID = 1L;

  private final Instant expiredAt;

  public AccessTokenExpiredException(Instant expiredAt) {
    this.expiredAt = expiredAt;
  }

  public Instant getExpiredAt() {
    return this.expiredAt;
  }

  @Override
  public String getMessage() {
    return "Token has expired since " + this.expiredAt;
  }
}

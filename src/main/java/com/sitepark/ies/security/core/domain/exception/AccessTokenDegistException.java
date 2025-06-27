package com.sitepark.ies.security.core.domain.exception;

/**
 * The <code>AccessTokenDegistException</code> exception is thrown if the access token could't be
 * digest.
 */
public class AccessTokenDegistException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  public AccessTokenDegistException(String message) {
    super(message);
  }

  public AccessTokenDegistException(String message, Throwable t) {
    super(message, t);
  }
}

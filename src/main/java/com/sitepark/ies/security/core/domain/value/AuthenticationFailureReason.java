package com.sitepark.ies.security.core.domain.value;

/**
 * Why a login failed although the credentials were correct. It is only given after the password
 * (or the identity provider) has confirmed the user, so it reveals nothing to someone guessing.
 */
public enum AuthenticationFailureReason {
  /** The deadline for setting up a second factor has expired. */
  SECOND_FACTOR_REQUIRED,
  /** The deadline for switching to a passkey has expired; the password no longer works. */
  PASSKEY_REQUIRED
}

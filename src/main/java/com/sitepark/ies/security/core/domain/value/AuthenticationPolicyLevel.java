package com.sitepark.ies.security.core.domain.value;

/** What a user must use to log in, as required by an administrator. */
public enum AuthenticationPolicyLevel {
  /** No requirement: the password alone is enough unless the user set up a second factor. */
  NONE,
  /** A login with the password must be completed with a second factor. */
  SECOND_FACTOR,
  /** The user logs in with a passkey only; the password no longer works. */
  PASSKEY
}

package com.sitepark.ies.security.core.domain.value;

/** A kind of second factor that an installation can allow or switch off. */
public enum AuthFactorType {
  /** One-time code of an authenticator app. */
  TOTP,
  /** One-time code sent to the e-mail address of the account. */
  EMAIL_CODE,
  /** Passkey (WebAuthn), which replaces password and second factor. */
  PASSKEY
}

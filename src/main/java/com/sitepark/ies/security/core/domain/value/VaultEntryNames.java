package com.sitepark.ies.security.core.domain.value;

public final class VaultEntryNames {
  public static final String TOTP_SECRET = "totp.secret";

  /** A new TOTP secret that becomes {@link #TOTP_SECRET} once a code of it is confirmed. */
  public static final String TOTP_SECRET_PENDING = "totp.secret.pending";

  private VaultEntryNames() {}
}

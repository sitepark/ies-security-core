package com.sitepark.ies.security.core.domain.value;

public enum AuthenticationRequirement {
  TOTP_CODE_REQUIRED,
  PASSKEY_CHALLENGE_REQUIRED,
  OAUTH_REDIRECT_REQUIRED
}

package com.sitepark.ies.security.core.port;

public interface AccessControl {
  boolean isImpersonationTokensManageable();

  boolean isGenerateTotpUrlAllowed(String userId);

  boolean isRemoveTotpSecretAllowed(String userId);

  boolean isWebAuthnRegistrationAllowed(String userId);

  boolean isWebAuthnGetRegisteredCredentialsAllowed(String userId);

  boolean isWebAuthnRemoveRegisteredCredentialsAllowed(String id);
}

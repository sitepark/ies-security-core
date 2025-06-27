package com.sitepark.ies.security.core.port;

@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface AccessControl {
  boolean isImpersonationTokensManageable();

  boolean isGenerateTotpUrlAllowed(String userId);

  boolean isRemoveTotpSecretAllowed(String userId);
}

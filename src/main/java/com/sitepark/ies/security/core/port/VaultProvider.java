package com.sitepark.ies.security.core.port;

public interface VaultProvider {
  Vault getUserVault(String userId);

  Vault getTenantVault();

  Vault getServerVault();
}

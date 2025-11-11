package com.sitepark.ies.security.core.usecase.totp;

import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.value.VaultEntryNames;
import com.sitepark.ies.security.core.port.VaultProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import jakarta.inject.Inject;

public class RemoveTotpSecretUseCase {

  private final VaultProvider vaultProvider;
  private final AccessControl accessControl;

  @Inject
  protected RemoveTotpSecretUseCase(VaultProvider vaultProvider, AccessControl accessControl) {
    this.vaultProvider = vaultProvider;
    this.accessControl = accessControl;
  }

  public void removeTotpSecret(String userId) {

    if (!this.accessControl.isGenerateTotpUrlAllowed(userId)) {
      throw new AccessDeniedException("Remove TOTP secret not allowed for user: " + userId);
    }

    this.vaultProvider.getUserVault(userId).deleteSecret(VaultEntryNames.TOTP_SECRET);
  }
}

package com.sitepark.ies.security.core.usecase.emailcode;

import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.value.VaultEntryNames;
import com.sitepark.ies.security.core.port.VaultProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import jakarta.inject.Inject;

/** Removes the e-mail code as second factor; possible even if the installation switched it off. */
public class RemoveEmailCodeUseCase {

  private final AccessControl accessControl;
  private final VaultProvider vaultProvider;

  @Inject
  protected RemoveEmailCodeUseCase(AccessControl accessControl, VaultProvider vaultProvider) {
    this.accessControl = accessControl;
    this.vaultProvider = vaultProvider;
  }

  public void removeEmailCode(String userId) {
    if (!this.accessControl.isEmailCodeManageable(userId)) {
      throw new AccessDeniedException(
          "Removing the e-mail code is not allowed for user: " + userId);
    }
    this.vaultProvider.getUserVault(userId).deleteSecret(VaultEntryNames.EMAIL_CODE_ADDRESS);
  }
}

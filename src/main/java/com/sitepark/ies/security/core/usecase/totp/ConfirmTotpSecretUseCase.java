package com.sitepark.ies.security.core.usecase.totp;

import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.service.AuthenticationPolicyService;
import com.sitepark.ies.security.core.domain.value.AuthFactorType;
import com.sitepark.ies.security.core.domain.value.VaultEntryNames;
import com.sitepark.ies.security.core.port.TotpProvider;
import com.sitepark.ies.security.core.port.Vault;
import com.sitepark.ies.security.core.port.VaultProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import jakarta.inject.Inject;

/**
 * Activates the TOTP secret that {@link GenerateTotpUrlUseCase} created, once the user has entered
 * a valid code of it. Until then a former secret stays in use, so an aborted setup does not lock
 * the user out.
 */
public class ConfirmTotpSecretUseCase {

  private final TotpProvider totpProvider;
  private final VaultProvider vaultProvider;
  private final AccessControl accessControl;

  private final AuthenticationPolicyService policyService;

  @Inject
  protected ConfirmTotpSecretUseCase(
      TotpProvider totpProvider,
      VaultProvider vaultProvider,
      AccessControl accessControl,
      AuthenticationPolicyService policyService) {
    this.policyService = policyService;
    this.totpProvider = totpProvider;
    this.vaultProvider = vaultProvider;
    this.accessControl = accessControl;
  }

  /**
   * Returns {@code true} if the code was valid and the secret is active now, {@code false} if there
   * is no secret to confirm or the code was wrong.
   */
  public boolean confirmTotpSecret(String userId, int totpCode) {
    this.policyService.requireFactorAllowed(AuthFactorType.TOTP);
    if (!this.accessControl.isGenerateTotpUrlAllowed(userId)) {
      throw new AccessDeniedException(
          "Confirming a TOTP secret is not allowed for user: " + userId);
    }
    Vault vault = this.vaultProvider.getUserVault(userId);
    if (!vault.hasSecret(VaultEntryNames.TOTP_SECRET_PENDING)) {
      return false;
    }
    String secret = vault.loadSecret(VaultEntryNames.TOTP_SECRET_PENDING);
    if (!this.totpProvider.validateTotpCode(secret, totpCode)) {
      return false;
    }
    vault.storeSecret(VaultEntryNames.TOTP_SECRET, secret);
    vault.deleteSecret(VaultEntryNames.TOTP_SECRET_PENDING);
    return true;
  }
}

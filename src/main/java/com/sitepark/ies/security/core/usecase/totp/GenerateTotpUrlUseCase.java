package com.sitepark.ies.security.core.usecase.totp;

import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.value.TotpUrl;
import com.sitepark.ies.security.core.domain.value.VaultEntryNames;
import com.sitepark.ies.security.core.port.TotpProvider;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.security.core.port.VaultProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;

public class GenerateTotpUrlUseCase {

  private final TotpProvider totpProvider;
  private final AccessControl accessControl;
  private final UserService userService;
  private final VaultProvider vaultProvider;

  @Inject
  protected GenerateTotpUrlUseCase(
      TotpProvider totpProvider,
      VaultProvider vaultProvider,
      AccessControl accessControl,
      UserService userService) {
    this.totpProvider = totpProvider;
    this.vaultProvider = vaultProvider;
    this.accessControl = accessControl;
    this.userService = userService;
  }

  public TotpUrl generateTotpUrl(String userId, String issuer) {

    if (!this.accessControl.isGenerateTotpUrlAllowed(userId)) {
      throw this.createAccessDeniedException(userId);
    }

    User user =
        this.userService
            .findById(userId)
            .orElseThrow(() -> this.createAccessDeniedException(userId));

    String secret = this.totpProvider.generateSecret();
    this.vaultProvider.getUserVault(user.id()).storeSecret(VaultEntryNames.TOTP_SECRET, secret);
    return new TotpUrl(issuer, user.username(), secret);
  }

  private AccessDeniedException createAccessDeniedException(String userId) {
    return new AccessDeniedException("Generating TOTP URL is not allowed for user: " + userId);
  }
}

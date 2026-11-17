package com.sitepark.ies.security.core.usecase.emailcode;

import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.service.AuthenticationPolicyService;
import com.sitepark.ies.security.core.domain.value.AuthFactorType;
import com.sitepark.ies.security.core.domain.value.EmailCodeSetupPayload;
import com.sitepark.ies.security.core.domain.value.VaultEntryNames;
import com.sitepark.ies.security.core.port.Vault;
import com.sitepark.ies.security.core.port.VaultProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.CodeVerificationChallenge;
import com.sitepark.ies.sharedkernel.security.CodeVerificationFailedException;
import com.sitepark.ies.sharedkernel.security.CodeVerificationService;
import jakarta.inject.Inject;

/**
 * Activates the e-mail code as second factor of a user once the code of {@link
 * StartEmailCodeSetupUseCase} is entered. A user has one code factor: the TOTP secret is removed.
 */
public class ConfirmEmailCodeSetupUseCase {

  private final AccessControl accessControl;
  private final AuthenticationPolicyService policyService;
  private final CodeVerificationService codeVerificationService;
  private final VaultProvider vaultProvider;

  @Inject
  protected ConfirmEmailCodeSetupUseCase(
      AccessControl accessControl,
      AuthenticationPolicyService policyService,
      CodeVerificationService codeVerificationService,
      VaultProvider vaultProvider) {
    this.accessControl = accessControl;
    this.policyService = policyService;
    this.codeVerificationService = codeVerificationService;
    this.vaultProvider = vaultProvider;
  }

  /** Returns whether the code was valid and the e-mail code is active now. */
  public boolean confirmEmailCodeSetup(String userId, String challengeId, int code) {
    this.policyService.requireFactorAllowed(AuthFactorType.EMAIL_CODE);
    if (!this.accessControl.isEmailCodeManageable(userId)) {
      throw new AccessDeniedException(
          "Confirming the e-mail code is not allowed for user: " + userId);
    }
    CodeVerificationChallenge challenge;
    try {
      challenge = this.codeVerificationService.finishChallenge(challengeId, code);
    } catch (CodeVerificationFailedException e) {
      return false;
    }
    if (!(challenge.payload() instanceof EmailCodeSetupPayload(String payloadUser, String address))
        || !payloadUser.equals(userId)) {
      return false;
    }
    Vault vault = this.vaultProvider.getUserVault(userId);
    vault.storeSecret(VaultEntryNames.EMAIL_CODE_ADDRESS, address);
    vault.deleteSecret(VaultEntryNames.TOTP_SECRET);
    vault.deleteSecret(VaultEntryNames.TOTP_SECRET_PENDING);
    return true;
  }
}

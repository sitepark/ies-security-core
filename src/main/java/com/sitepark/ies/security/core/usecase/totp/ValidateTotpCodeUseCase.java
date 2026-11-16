package com.sitepark.ies.security.core.usecase.totp;

import com.sitepark.ies.security.core.domain.exception.AuthenticationProcessNotFoundException;
import com.sitepark.ies.security.core.domain.exception.TotpNotRequiredException;
import com.sitepark.ies.security.core.domain.service.AuthenticationPolicyService;
import com.sitepark.ies.security.core.domain.value.AuthenticationFailureReason;
import com.sitepark.ies.security.core.domain.value.AuthenticationRequirement;
import com.sitepark.ies.security.core.domain.value.AuthenticationResult;
import com.sitepark.ies.security.core.domain.value.PartialAuthenticationState;
import com.sitepark.ies.security.core.domain.value.PolicyDecision;
import com.sitepark.ies.security.core.domain.value.VaultEntryNames;
import com.sitepark.ies.security.core.port.TotpAuthenticationProcessStore;
import com.sitepark.ies.security.core.port.TotpProvider;
import com.sitepark.ies.security.core.port.VaultProvider;
import jakarta.inject.Inject;
import java.util.List;

public class ValidateTotpCodeUseCase {

  private final TotpProvider totpProvider;
  private final VaultProvider vaultProvider;
  private final TotpAuthenticationProcessStore authenticationProcessStore;
  private final AuthenticationPolicyService policyService;

  @Inject
  protected ValidateTotpCodeUseCase(
      TotpProvider totpProvider,
      VaultProvider vaultProvider,
      TotpAuthenticationProcessStore authenticationProcessStore,
      AuthenticationPolicyService policyService) {
    this.totpProvider = totpProvider;
    this.vaultProvider = vaultProvider;
    this.authenticationProcessStore = authenticationProcessStore;
    this.policyService = policyService;
  }

  public AuthenticationResult validateTotpCode(String authProcessId, int totpCode) {

    PartialAuthenticationState authState =
        this.authenticationProcessStore
            .retrieve(authProcessId)
            .orElseThrow(AuthenticationProcessNotFoundException::new);

    boolean codeRequired =
        authState.requirements().stream()
            .anyMatch(requirement -> requirement == AuthenticationRequirement.TOTP_CODE_REQUIRED);

    if (!codeRequired) {
      throw new TotpNotRequiredException();
    }

    String secret =
        this.vaultProvider
            .getUserVault(authState.user().id())
            .loadSecret(VaultEntryNames.TOTP_SECRET);

    boolean isValid = this.totpProvider.validateTotpCode(secret, totpCode);
    if (!isValid) {
      return AuthenticationResult.failure();
    }

    List<AuthenticationRequirement> remainingRequirements =
        authState.requirements().stream()
            .filter(requirement -> requirement != AuthenticationRequirement.TOTP_CODE_REQUIRED)
            .toList();

    if (remainingRequirements.isEmpty()) {
      this.authenticationProcessStore.remove(authProcessId);
      // decided again because the deadline may have expired since the password step
      PolicyDecision decision = this.policyService.decidePasswordLogin(authState.user(), true);
      if (decision instanceof PolicyDecision.Denied(AuthenticationFailureReason reason)) {
        return AuthenticationResult.failure(reason);
      }
      return AuthenticationResult.success(authState.user(), authState.purpose())
          .withPolicyNotice(((PolicyDecision.Allowed) decision).notice());
    }

    return AuthenticationResult.partial(authProcessId, remainingRequirements);
  }
}

package com.sitepark.ies.security.core.usecase;

import com.sitepark.ies.security.core.domain.value.AuthenticationRequirement;
import com.sitepark.ies.security.core.domain.value.PartialAuthenticationState;
import com.sitepark.ies.security.core.domain.value.VaultEntryNames;
import com.sitepark.ies.security.core.port.MfaAuthenticationProcessStore;
import com.sitepark.ies.security.core.port.TotpProvider;
import com.sitepark.ies.security.core.port.VaultProvider;
import com.sitepark.ies.security.core.usecase.authentication.AuthenticationResult;
import jakarta.inject.Inject;
import java.util.Arrays;

public class ValidateTotpCodeUseCase {

  private final TotpProvider totpProvider;
  private final VaultProvider vaultProvider;
  private final MfaAuthenticationProcessStore authenticationProcessStore;

  @Inject
  protected ValidateTotpCodeUseCase(
      TotpProvider totpProvider,
      VaultProvider vaultProvider,
      MfaAuthenticationProcessStore authenticationProcessStore) {
    this.totpProvider = totpProvider;
    this.vaultProvider = vaultProvider;
    this.authenticationProcessStore = authenticationProcessStore;
  }

  public AuthenticationResult validateTotpCode(String authProcessId, int totpCode) {

    PartialAuthenticationState authState =
        this.authenticationProcessStore
            .retrieve(authProcessId)
            .orElseThrow(
                () ->
                    new IllegalArgumentException(
                        "Authentication process not found: " + authProcessId));

    boolean codeRequired =
        Arrays.stream(authState.requirements())
            .anyMatch(requirement -> requirement == AuthenticationRequirement.TOTP_CODE_REQUIRED);

    if (!codeRequired) {
      throw new IllegalArgumentException(
          "TOTP code validation is not required for this authentication process: " + authProcessId);
    }

    String secret =
        this.vaultProvider
            .getUserVault(authState.user().id())
            .loadSecret(VaultEntryNames.TOTP_SECRET);

    boolean isValid = this.totpProvider.validateTotpCode(secret, totpCode);
    if (!isValid) {
      return AuthenticationResult.failure();
    }

    AuthenticationRequirement[] remainingRequirements =
        Arrays.stream(authState.requirements())
            .filter(requirement -> requirement != AuthenticationRequirement.TOTP_CODE_REQUIRED)
            .toArray(AuthenticationRequirement[]::new);

    if (remainingRequirements.length == 0) {
      return AuthenticationResult.success(authState.user(), authState.purpose());
    }

    return AuthenticationResult.partial(authProcessId, remainingRequirements);
  }
}

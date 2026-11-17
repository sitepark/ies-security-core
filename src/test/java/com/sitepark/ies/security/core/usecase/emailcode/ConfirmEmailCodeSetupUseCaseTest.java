package com.sitepark.ies.security.core.usecase.emailcode;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.service.AuthenticationPolicyService;
import com.sitepark.ies.security.core.domain.value.EmailCodeSetupPayload;
import com.sitepark.ies.security.core.domain.value.VaultEntryNames;
import com.sitepark.ies.security.core.port.Vault;
import com.sitepark.ies.security.core.port.VaultProvider;
import com.sitepark.ies.sharedkernel.security.CodeVerificationChallenge;
import com.sitepark.ies.sharedkernel.security.CodeVerificationFailedException;
import com.sitepark.ies.sharedkernel.security.CodeVerificationService;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ConfirmEmailCodeSetupUseCaseTest {

  private static final Instant NOW = Instant.parse("2026-11-17T10:00:00Z");

  private CodeVerificationService codeVerificationService;
  private Vault vault;
  private ConfirmEmailCodeSetupUseCase useCase;

  @BeforeEach
  void setUp() {
    AccessControl accessControl = mock();
    when(accessControl.isEmailCodeManageable("7")).thenReturn(true);
    this.codeVerificationService = mock();
    this.vault = mock();
    VaultProvider vaultProvider = mock();
    when(vaultProvider.getUserVault("7")).thenReturn(this.vault);
    this.useCase =
        new ConfirmEmailCodeSetupUseCase(
            accessControl,
            mock(AuthenticationPolicyService.class),
            this.codeVerificationService,
            vaultProvider);
  }

  private CodeVerificationChallenge challenge(String userId) {
    return new CodeVerificationChallenge(
        "c-1",
        123_456,
        new EmailCodeSetupPayload(userId, "p@example.org"),
        NOW,
        NOW.plusSeconds(600),
        0);
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testWrongCode() {
    when(this.codeVerificationService.finishChallenge("c-1", 1))
        .thenThrow(new CodeVerificationFailedException("wrong"));
    assertFalse(this.useCase.confirmEmailCodeSetup("7", "c-1", 1), "a wrong code must not confirm");
    verify(this.vault, never()).storeSecret(any(), any());
  }

  @Test
  void testChallengeOfOtherUser() {
    when(this.codeVerificationService.finishChallenge("c-1", 123_456))
        .thenReturn(this.challenge("8"));
    assertFalse(
        this.useCase.confirmEmailCodeSetup("7", "c-1", 123_456),
        "a challenge of another user must not confirm");
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testConfirmReplacesTotp() {
    when(this.codeVerificationService.finishChallenge("c-1", 123_456))
        .thenReturn(this.challenge("7"));
    assertTrue(this.useCase.confirmEmailCodeSetup("7", "c-1", 123_456), "a valid code confirms");
    verify(this.vault).storeSecret(VaultEntryNames.EMAIL_CODE_ADDRESS, "p@example.org");
    verify(this.vault).deleteSecret(VaultEntryNames.TOTP_SECRET);
  }
}

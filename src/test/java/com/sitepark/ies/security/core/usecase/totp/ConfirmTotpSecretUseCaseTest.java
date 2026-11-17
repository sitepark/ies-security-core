package com.sitepark.ies.security.core.usecase.totp;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.service.AuthenticationPolicyService;
import com.sitepark.ies.security.core.domain.value.VaultEntryNames;
import com.sitepark.ies.security.core.port.TotpProvider;
import com.sitepark.ies.security.core.port.Vault;
import com.sitepark.ies.security.core.port.VaultProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ConfirmTotpSecretUseCaseTest {

  private TotpProvider totpProvider;
  private AccessControl accessControl;
  private Vault vault;
  private ConfirmTotpSecretUseCase useCase;

  @BeforeEach
  void setUp() {
    this.totpProvider = mock();
    this.accessControl = mock();
    this.vault = mock();
    VaultProvider vaultProvider = mock();
    when(vaultProvider.getUserVault("7")).thenReturn(this.vault);
    this.useCase =
        new ConfirmTotpSecretUseCase(
            this.totpProvider,
            vaultProvider,
            this.accessControl,
            mock(AuthenticationPolicyService.class));
  }

  @Test
  void testAccessDenied() {
    assertThrows(
        AccessDeniedException.class,
        () -> this.useCase.confirmTotpSecret("7", 123_456),
        "confirming must need access");
  }

  @Test
  void testNothingToConfirm() {
    when(this.accessControl.isGenerateTotpUrlAllowed("7")).thenReturn(true);
    assertFalse(
        this.useCase.confirmTotpSecret("7", 123_456), "without a pending secret nothing is active");
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testWrongCodeKeepsFormerSecret() {
    when(this.accessControl.isGenerateTotpUrlAllowed("7")).thenReturn(true);
    when(this.vault.hasSecret(VaultEntryNames.TOTP_SECRET_PENDING)).thenReturn(true);
    when(this.vault.loadSecret(VaultEntryNames.TOTP_SECRET_PENDING)).thenReturn("new");
    when(this.totpProvider.validateTotpCode("new", 123_456)).thenReturn(false);

    assertFalse(this.useCase.confirmTotpSecret("7", 123_456), "a wrong code must not activate");
    verify(this.vault, never()).storeSecret(anyString(), any());
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testConfirm() {
    when(this.accessControl.isGenerateTotpUrlAllowed("7")).thenReturn(true);
    when(this.vault.hasSecret(VaultEntryNames.TOTP_SECRET_PENDING)).thenReturn(true);
    when(this.vault.loadSecret(VaultEntryNames.TOTP_SECRET_PENDING)).thenReturn("new");
    when(this.totpProvider.validateTotpCode("new", 123_456)).thenReturn(true);

    assertTrue(this.useCase.confirmTotpSecret("7", 123_456), "a valid code must activate");
    verify(this.vault).storeSecret(VaultEntryNames.TOTP_SECRET, "new");
    verify(this.vault).deleteSecret(VaultEntryNames.TOTP_SECRET_PENDING);
    verify(this.vault).deleteSecret(VaultEntryNames.EMAIL_CODE_ADDRESS);
  }
}

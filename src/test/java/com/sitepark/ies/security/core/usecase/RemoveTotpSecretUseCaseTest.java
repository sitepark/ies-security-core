package com.sitepark.ies.security.core.usecase;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.sitepark.ies.security.core.domain.value.VaultEntryNames;
import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.Vault;
import com.sitepark.ies.security.core.port.VaultProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RemoveTotpSecretUseCaseTest {

  private VaultProvider vaultProvider;
  private AccessControl accessControl;

  private RemoveTotpSecretUseCase useCase;

  @BeforeEach
  void setUp() {
    this.vaultProvider = mock();
    this.accessControl = mock();

    this.useCase = new RemoveTotpSecretUseCase(vaultProvider, accessControl);
  }

  @Test
  void testAccessControl() {
    when(accessControl.isGenerateTotpUrlAllowed(any())).thenReturn(false);
    assertThrows(
        AccessDeniedException.class,
        () -> useCase.removeTotpSecret("userId"),
        "Expected AccessDeniedException to be thrown");
  }

  @Test
  void removeTotpSecretSuccess() {
    String userId = "userId";
    when(accessControl.isGenerateTotpUrlAllowed(userId)).thenReturn(true);

    Vault vault = mock();
    when(vaultProvider.getUserVault(any())).thenReturn(vault);

    useCase.removeTotpSecret(userId);

    verify(vault).deleteSecret(VaultEntryNames.TOTP_SECRET);
  }
}

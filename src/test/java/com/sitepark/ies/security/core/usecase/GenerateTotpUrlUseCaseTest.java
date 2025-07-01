package com.sitepark.ies.security.core.usecase;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.value.TotpUrl;
import com.sitepark.ies.security.core.domain.value.VaultEntryNames;
import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.TotpProvider;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.security.core.port.Vault;
import com.sitepark.ies.security.core.port.VaultProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class GenerateTotpUrlUseCaseTest {

  private TotpProvider totpProvider;
  private AccessControl accessControl;
  private UserService userService;
  private VaultProvider vaultProvider;

  private GenerateTotpUrlUseCase useCase;

  @BeforeEach
  void setUp() {
    this.totpProvider = mock();
    this.accessControl = mock();
    this.userService = mock();
    this.vaultProvider = mock();

    this.useCase =
        new GenerateTotpUrlUseCase(
            this.totpProvider, this.vaultProvider, this.accessControl, this.userService);
  }

  @Test
  void testAccessControl() {
    assertThrows(
        AccessDeniedException.class, () -> this.useCase.generateTotpUrl("userId", "issuer"));
  }

  @Test
  void testUserNotFound() {
    when(this.accessControl.isGenerateTotpUrlAllowed("1")).thenReturn(true);
    when(this.userService.findById(any())).thenReturn(Optional.empty());
    assertThrows(
        AccessDeniedException.class, () -> this.useCase.generateTotpUrl("userId", "issuer"));
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testGenerateTotpUrl() {
    when(this.accessControl.isGenerateTotpUrlAllowed("123")).thenReturn(true);
    User user =
        User.builder().id("123").username("peterpan").firstName("Peter").lastName("Pan").build();
    when(this.userService.findById(any())).thenReturn(Optional.of(user));
    when(this.totpProvider.generateSecret()).thenReturn("secret");

    Vault userVault = mock();
    when(this.vaultProvider.getUserVault("123")).thenReturn(userVault);

    TotpUrl totpUrl = this.useCase.generateTotpUrl("123", "issuer");

    TotpUrl expectedTotpUrl = new TotpUrl("issuer", "peterpan", "secret");

    assertEquals(expectedTotpUrl, totpUrl, "Generated TOTP URL does not match expected value");

    verify(userVault).storeSecret(VaultEntryNames.TOTP_SECRET, "secret");
  }
}

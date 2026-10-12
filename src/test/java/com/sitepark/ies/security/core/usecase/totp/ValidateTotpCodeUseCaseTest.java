package com.sitepark.ies.security.core.usecase.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.exception.AuthenticationProcessNotFoundException;
import com.sitepark.ies.security.core.domain.exception.TotpNotRequiredException;
import com.sitepark.ies.security.core.domain.value.AuthenticationRequirement;
import com.sitepark.ies.security.core.domain.value.AuthenticationResult;
import com.sitepark.ies.security.core.domain.value.PartialAuthenticationState;
import com.sitepark.ies.security.core.port.TotpAuthenticationProcessStore;
import com.sitepark.ies.security.core.port.TotpProvider;
import com.sitepark.ies.security.core.port.Vault;
import com.sitepark.ies.security.core.port.VaultProvider;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ValidateTotpCodeUseCaseTest {
  private TotpProvider totpProvider;
  private VaultProvider vaultProvider;
  private TotpAuthenticationProcessStore authenticationProcessStore;

  private ValidateTotpCodeUseCase useCase;

  @BeforeEach
  void setUp() {
    this.totpProvider = mock(TotpProvider.class);
    this.vaultProvider = mock(VaultProvider.class);
    this.authenticationProcessStore = mock(TotpAuthenticationProcessStore.class);

    this.useCase =
        new ValidateTotpCodeUseCase(totpProvider, vaultProvider, authenticationProcessStore);
  }

  @Test
  void testInvalidProcessId() {
    when(this.authenticationProcessStore.retrieve(any())).thenReturn(Optional.empty());
    assertThrows(
        AuthenticationProcessNotFoundException.class,
        () -> {
          this.useCase.validateTotpCode("testProcessId", 123456);
        },
        "unknown process must be reported");
  }

  @Test
  void testCodeNotRequired() {
    PartialAuthenticationState authState =
        new PartialAuthenticationState(
            null, null, List.of(AuthenticationRequirement.PASSKEY_CHALLENGE_REQUIRED), null, null);

    when(this.authenticationProcessStore.retrieve(any())).thenReturn(Optional.of(authState));

    assertThrows(
        TotpNotRequiredException.class,
        () -> {
          this.useCase.validateTotpCode("testProcessId", 123456);
        },
        "missing TOTP requirement must be reported");
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testInvalidSecret() {

    User user = User.builder().id("123").username("peterpan").lastName("Pan").build();
    PartialAuthenticationState authState =
        new PartialAuthenticationState(
            user, null, List.of(AuthenticationRequirement.TOTP_CODE_REQUIRED), null, null);

    Vault userVault = mock();
    when(this.vaultProvider.getUserVault(any())).thenReturn(userVault);
    when(this.authenticationProcessStore.retrieve(any())).thenReturn(Optional.of(authState));
    when(userVault.loadSecret(any())).thenReturn("secret");

    when(this.totpProvider.validateTotpCode(any(), anyInt())).thenReturn(false);

    assertEquals(
        AuthenticationResult.failure(),
        this.useCase.validateTotpCode("testProcessId", 123456),
        "Expected failure due to invalid TOTP code");
    verify(this.authenticationProcessStore, never()).remove(any());
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testSuccess() {
    User user = User.builder().id("123").username("peterpan").lastName("Pan").build();
    PartialAuthenticationState authState =
        new PartialAuthenticationState(
            user, null, List.of(AuthenticationRequirement.TOTP_CODE_REQUIRED), null, "purpose");

    Vault userVault = mock();
    when(this.vaultProvider.getUserVault(any())).thenReturn(userVault);
    when(this.authenticationProcessStore.retrieve(any())).thenReturn(Optional.of(authState));
    when(userVault.loadSecret(any())).thenReturn("secret");

    when(this.totpProvider.validateTotpCode(any(), anyInt())).thenReturn(true);

    assertEquals(
        AuthenticationResult.success(user, "purpose"),
        this.useCase.validateTotpCode("testProcessId", 123456),
        "Expected successful TOTP code validation");
    verify(this.authenticationProcessStore).remove("testProcessId");
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testPartial() {
    User user = User.builder().id("123").username("peterpan").lastName("Pan").build();
    PartialAuthenticationState authState =
        new PartialAuthenticationState(
            user,
            null,
            List.of(
                AuthenticationRequirement.TOTP_CODE_REQUIRED,
                AuthenticationRequirement.PASSKEY_CHALLENGE_REQUIRED),
            null,
            null);

    Vault userVault = mock();
    when(this.vaultProvider.getUserVault(any())).thenReturn(userVault);
    when(this.authenticationProcessStore.retrieve(any())).thenReturn(Optional.of(authState));
    when(userVault.loadSecret(any())).thenReturn("secret");

    when(this.totpProvider.validateTotpCode(any(), anyInt())).thenReturn(true);

    assertEquals(
        AuthenticationResult.partial(
            "testProcessId", List.of(AuthenticationRequirement.PASSKEY_CHALLENGE_REQUIRED)),
        this.useCase.validateTotpCode("testProcessId", 123456),
        "Expected successful TOTP code validation");
    verify(this.authenticationProcessStore, never()).remove(any());
  }
}

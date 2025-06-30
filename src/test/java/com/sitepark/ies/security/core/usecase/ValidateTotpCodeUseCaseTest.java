package com.sitepark.ies.security.core.usecase;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.entity.AuthenticatedUser;
import com.sitepark.ies.security.core.domain.value.AuthenticationRequirement;
import com.sitepark.ies.security.core.domain.value.PartialAuthenticationState;
import com.sitepark.ies.security.core.port.AuthenticationProcessStore;
import com.sitepark.ies.security.core.port.TotpProvider;
import com.sitepark.ies.security.core.port.Vault;
import com.sitepark.ies.security.core.port.VaultProvider;
import com.sitepark.ies.security.core.usecase.authentication.AuthenticationResult;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ValidateTotpCodeUseCaseTest {
  private TotpProvider totpProvider;
  private VaultProvider vaultProvider;
  private AuthenticationProcessStore authenticationProcessStore;

  private ValidateTotpCodeUseCase useCase;

  @BeforeEach
  void setUp() {
    this.totpProvider = mock(TotpProvider.class);
    this.vaultProvider = mock(VaultProvider.class);
    this.authenticationProcessStore = mock(AuthenticationProcessStore.class);

    this.useCase =
        new ValidateTotpCodeUseCase(totpProvider, vaultProvider, authenticationProcessStore);
  }

  @Test
  void testInvalidProcessId() {
    when(this.authenticationProcessStore.retrieve(any())).thenReturn(Optional.empty());
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          this.useCase.validateTotpCode("testProcessId", 123456);
        });
  }

  @Test
  void testCodeNotRequired() {
    PartialAuthenticationState authState =
        new PartialAuthenticationState(
            null,
            null,
            new AuthenticationRequirement[] {AuthenticationRequirement.PASSKEY_CHALLENGE_REQUIRED},
            null);

    when(this.authenticationProcessStore.retrieve(any())).thenReturn(Optional.of(authState));

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          this.useCase.validateTotpCode("testProcessId", 123456);
        });
  }

  @Test
  void testInvalidSecret() {

    User user =
        User.builder().id("123").username("peterpan").lastName("Pan").passwordHash("hash").build();
    PartialAuthenticationState authState =
        new PartialAuthenticationState(
            user,
            null,
            new AuthenticationRequirement[] {AuthenticationRequirement.TOTP_CODE_REQUIRED},
            null);

    Vault userVault = mock();
    when(this.vaultProvider.getUserVault(any())).thenReturn(userVault);
    when(this.authenticationProcessStore.retrieve(any())).thenReturn(Optional.of(authState));
    when(userVault.loadSecret(any())).thenReturn("secret");

    when(this.totpProvider.validateTotpCode(any(), anyInt())).thenReturn(false);

    assertEquals(
        AuthenticationResult.failure(),
        this.useCase.validateTotpCode("testProcessId", 123456),
        "Expected failure due to invalid TOTP code");
  }

  @Test
  void testSuccess() {
    User user =
        User.builder().id("123").username("peterpan").lastName("Pan").passwordHash("hash").build();
    PartialAuthenticationState authState =
        new PartialAuthenticationState(
            user,
            null,
            new AuthenticationRequirement[] {AuthenticationRequirement.TOTP_CODE_REQUIRED},
            null);

    Vault userVault = mock();
    when(this.vaultProvider.getUserVault(any())).thenReturn(userVault);
    when(this.authenticationProcessStore.retrieve(any())).thenReturn(Optional.of(authState));
    when(userVault.loadSecret(any())).thenReturn("secret");

    when(this.totpProvider.validateTotpCode(any(), anyInt())).thenReturn(true);

    AuthenticatedUser expectedUser = AuthenticatedUser.fromUser(user);

    assertEquals(
        AuthenticationResult.success(expectedUser),
        this.useCase.validateTotpCode("testProcessId", 123456),
        "Expected successful TOTP code validation");
  }

  @Test
  void testPartial() {
    User user =
        User.builder().id("123").username("peterpan").lastName("Pan").passwordHash("hash").build();
    PartialAuthenticationState authState =
        new PartialAuthenticationState(
            user,
            null,
            new AuthenticationRequirement[] {
              AuthenticationRequirement.TOTP_CODE_REQUIRED,
              AuthenticationRequirement.PASSKEY_CHALLENGE_REQUIRED
            },
            null);

    Vault userVault = mock();
    when(this.vaultProvider.getUserVault(any())).thenReturn(userVault);
    when(this.authenticationProcessStore.retrieve(any())).thenReturn(Optional.of(authState));
    when(userVault.loadSecret(any())).thenReturn("secret");

    when(this.totpProvider.validateTotpCode(any(), anyInt())).thenReturn(true);

    assertEquals(
        AuthenticationResult.partial(
            "testProcessId",
            new AuthenticationRequirement[] {AuthenticationRequirement.PASSKEY_CHALLENGE_REQUIRED}),
        this.useCase.validateTotpCode("testProcessId", 123456),
        "Expected successful TOTP code validation");
  }
}

package com.sitepark.ies.security.core.usecase.emailcode;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.exception.EmailCodeNotRequiredException;
import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.service.EmailCodeService;
import com.sitepark.ies.security.core.domain.value.AuthenticationRequirement;
import com.sitepark.ies.security.core.domain.value.PartialAuthenticationState;
import com.sitepark.ies.security.core.domain.value.VaultEntryNames;
import com.sitepark.ies.security.core.port.TotpAuthenticationProcessStore;
import com.sitepark.ies.security.core.port.Vault;
import com.sitepark.ies.security.core.port.VaultProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.User;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class ResendAndRemoveEmailCodeUseCaseTest {

  private final User user = User.builder().id("7").username("peter").lastName("Pan").build();

  private static PartialAuthenticationState state(User user, AuthenticationRequirement req) {
    return new PartialAuthenticationState(
        user, AuthMethod.PASSWORD, List.of(req), Instant.parse("2026-11-17T10:00:00Z"), "p", "c-1");
  }

  @Test
  void testResend() {
    TotpAuthenticationProcessStore store = mock();
    EmailCodeService service = mock();
    when(store.retrieve("p-1"))
        .thenReturn(Optional.of(state(this.user, AuthenticationRequirement.EMAIL_CODE_REQUIRED)));

    new ResendEmailCodeUseCase(store, service).resendEmailCode("p-1");

    verify(service).resend(this.user);
  }

  @Test
  void testResendNotRequired() {
    TotpAuthenticationProcessStore store = mock();
    when(store.retrieve("p-1"))
        .thenReturn(Optional.of(state(this.user, AuthenticationRequirement.TOTP_CODE_REQUIRED)));
    ResendEmailCodeUseCase useCase = new ResendEmailCodeUseCase(store, mock());
    assertThrows(
        EmailCodeNotRequiredException.class,
        () -> useCase.resendEmailCode("p-1"),
        "a login without e-mail code must not send one");
  }

  @Test
  void testRemoveAccessDenied() {
    RemoveEmailCodeUseCase useCase = new RemoveEmailCodeUseCase(mock(), mock());
    assertThrows(
        AccessDeniedException.class,
        () -> useCase.removeEmailCode("7"),
        "removing must need access");
  }

  @Test
  void testRemove() {
    AccessControl accessControl = mock();
    when(accessControl.isEmailCodeManageable("7")).thenReturn(true);
    Vault vault = mock();
    VaultProvider vaultProvider = mock();
    when(vaultProvider.getUserVault("7")).thenReturn(vault);

    new RemoveEmailCodeUseCase(accessControl, vaultProvider).removeEmailCode("7");

    verify(vault).deleteSecret(VaultEntryNames.EMAIL_CODE_ADDRESS);
  }
}

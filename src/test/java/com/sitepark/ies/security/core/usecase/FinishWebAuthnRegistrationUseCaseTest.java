package com.sitepark.ies.security.core.usecase;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.sitepark.ies.security.core.domain.value.WebAuthnRegistrationCredential;
import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.security.core.port.WebAuthnProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class FinishWebAuthnRegistrationUseCaseTest {

  private UserService userService;
  private AccessControl accessControl;
  private WebAuthnProvider webAuthnProvider;

  private FinishWebAuthnRegistrationUseCase useCase;

  @BeforeEach
  void setUp() {
    this.userService = mock();
    this.accessControl = mock();
    this.webAuthnProvider = mock();

    this.useCase =
        new FinishWebAuthnRegistrationUseCase(userService, accessControl, webAuthnProvider);
  }

  @Test
  void testAccessControl() {
    when(accessControl.isWebAuthnRegistrationAllowed(any())).thenReturn(false);
    assertThrows(
        AccessDeniedException.class,
        () -> {
          useCase.finishWebAuthnRegistration(new WebAuthnRegistrationCredential(null, null));
        });
  }

  @Test
  void testUserNotFound() {
    String userId = "user123";
    when(accessControl.isWebAuthnRegistrationAllowed(any())).thenReturn(true);
    when(userService.findById(userId)).thenReturn(Optional.empty());
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          useCase.finishWebAuthnRegistration(new WebAuthnRegistrationCredential(userId, null));
        });
  }

  @Test
  void testFinishWebAuthnRegistration() {
    when(accessControl.isWebAuthnRegistrationAllowed(any())).thenReturn(true);
    User user = User.builder().id("123").username("peterpan").lastName("Pan").build();
    when(userService.findById(any())).thenReturn(Optional.of(user));

    WebAuthnRegistrationCredential credential = new WebAuthnRegistrationCredential("key", "123");
    this.useCase.finishWebAuthnRegistration(credential);

    verify(this.webAuthnProvider).finishRegistration(credential);
  }
}

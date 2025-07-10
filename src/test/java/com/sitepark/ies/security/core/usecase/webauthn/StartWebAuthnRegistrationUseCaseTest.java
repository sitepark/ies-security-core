package com.sitepark.ies.security.core.usecase.webauthn;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.security.core.port.WebAuthnProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.User;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class StartWebAuthnRegistrationUseCaseTest {

  private UserService userService;
  private AccessControl accessControl;
  private WebAuthnProvider webAuthnProvider;

  private StartWebAuthnRegistrationUseCase useCase;

  @BeforeEach
  void setUp() {
    this.userService = mock();
    this.accessControl = mock();
    this.webAuthnProvider = mock();

    this.useCase =
        new StartWebAuthnRegistrationUseCase(userService, accessControl, webAuthnProvider);
  }

  @Test
  void testWithInvalidOrigin() {
    String invalidOrigin = ":htp//invalid-origin";
    WebAuthnRegistrationCommand command =
        new WebAuthnRegistrationCommand("user123", invalidOrigin, "Test App", "Test Key");

    assertThrows(IllegalArgumentException.class, () -> useCase.startWebAuthnRegistration(command));
  }

  @Test
  void testAccessControl() {

    when(accessControl.isWebAuthnRegistrationAllowed(any())).thenReturn(false);

    WebAuthnRegistrationCommand command =
        new WebAuthnRegistrationCommand(
            "user123", "https://valid-origin.com", "Test App", "Test Key");

    assertThrows(AccessDeniedException.class, () -> useCase.startWebAuthnRegistration(command));
  }

  @Test
  void testUserNotFound() {

    when(accessControl.isWebAuthnRegistrationAllowed(any())).thenReturn(true);

    WebAuthnRegistrationCommand command =
        new WebAuthnRegistrationCommand(
            "nonexistentUser", "https://valid-origin.com", "Test App", "Test Key");

    when(userService.findById(any())).thenReturn(Optional.empty());

    assertThrows(IllegalArgumentException.class, () -> useCase.startWebAuthnRegistration(command));
  }

  @Test
  void testValidRegistration() throws URISyntaxException {

    when(accessControl.isWebAuthnRegistrationAllowed(any())).thenReturn(true);
    User user = User.builder().id("123").username("peterpan").lastName("Pan").build();
    when(userService.findById(any())).thenReturn(Optional.of(user));

    WebAuthnRegistrationCommand command =
        new WebAuthnRegistrationCommand("123", "https://valid-origin.com", "Test App", "Test Key");

    this.useCase.startWebAuthnRegistration(command);

    verify(this.webAuthnProvider)
        .startRegistration(user, new URI("https://valid-origin.com"), "Test App", "Test Key");
  }
}

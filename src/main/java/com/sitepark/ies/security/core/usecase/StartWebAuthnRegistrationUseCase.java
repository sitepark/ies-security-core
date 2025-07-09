package com.sitepark.ies.security.core.usecase;

import com.sitepark.ies.security.core.domain.value.WebAuthnRegistrationStartResult;
import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.security.core.port.WebAuthnProvider;
import com.sitepark.ies.security.core.usecase.authentication.WebAuthnRegistrationCommand;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

public class StartWebAuthnRegistrationUseCase {

  private final UserService userService;
  private final AccessControl accessControl;
  private final WebAuthnProvider webAuthnProvider;

  @Inject
  protected StartWebAuthnRegistrationUseCase(
      UserService userService, AccessControl accessControl, WebAuthnProvider webAuthnProvider) {
    this.userService = userService;
    this.accessControl = accessControl;
    this.webAuthnProvider = webAuthnProvider;
  }

  public WebAuthnRegistrationStartResult startWebAuthnRegistration(
      WebAuthnRegistrationCommand command) {

    URI origin;
    try {
      origin = new URI(command.origin());
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Invalid origin: " + command.origin(), e);
    }

    if (!this.accessControl.isWebAuthnRegistrationAllowed(command.userId())) {
      throw new AccessDeniedException(
          "WebAuthn registration not allowed for user: " + command.userId());
    }

    Optional<User> user = this.userService.findById(command.userId());
    if (user.isEmpty()) {
      throw new IllegalArgumentException("User not found: " + command.userId());
    }

    return this.webAuthnProvider.startRegistration(
        user.get(), origin, command.applicationName(), command.keyName());
  }
}

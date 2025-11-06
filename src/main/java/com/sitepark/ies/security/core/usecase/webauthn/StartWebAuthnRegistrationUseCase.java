package com.sitepark.ies.security.core.usecase.webauthn;

import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.security.core.port.WebAuthnProvider;
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

  public String startWebAuthnRegistration(WebAuthnRegistrationRequest request) {

    URI origin;
    try {
      origin = new URI(request.origin());
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Invalid origin: " + request.origin(), e);
    }

    if (!this.accessControl.isWebAuthnRegistrationAllowed(request.userId())) {
      throw new AccessDeniedException(
          "WebAuthn registration not allowed for user: " + request.userId());
    }

    Optional<User> user = this.userService.findById(request.userId());
    if (user.isEmpty()) {
      throw new IllegalArgumentException("User not found: " + request.userId());
    }

    return this.webAuthnProvider.startRegistration(
        user.get(), origin, request.applicationName(), request.keyName());
  }
}

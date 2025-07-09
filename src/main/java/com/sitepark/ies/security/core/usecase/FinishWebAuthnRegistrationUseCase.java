package com.sitepark.ies.security.core.usecase;

import com.sitepark.ies.security.core.domain.value.WebAuthnRegistrationCredential;
import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.security.core.port.WebAuthnProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;
import java.util.Optional;

public class FinishWebAuthnRegistrationUseCase {

  private final UserService userService;
  private final AccessControl accessControl;
  private final WebAuthnProvider webAuthnProvider;

  @Inject
  protected FinishWebAuthnRegistrationUseCase(
      UserService userService, AccessControl accessControl, WebAuthnProvider webAuthnProvider) {
    this.userService = userService;
    this.accessControl = accessControl;
    this.webAuthnProvider = webAuthnProvider;
  }

  public void finishWebAuthnRegistration(WebAuthnRegistrationCredential credential) {

    if (!this.accessControl.isWebAuthnRegistrationAllowed(credential.userId())) {
      throw new AccessDeniedException(
          "WebAuthn registration not allowed for user: " + credential.userId());
    }

    Optional<User> user = this.userService.findById(credential.userId());
    if (user.isEmpty()) {
      throw new IllegalArgumentException("User not found: " + credential.userId());
    }

    this.webAuthnProvider.finishRegistration(credential);
  }
}

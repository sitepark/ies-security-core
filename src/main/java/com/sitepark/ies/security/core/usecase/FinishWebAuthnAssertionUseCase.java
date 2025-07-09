package com.sitepark.ies.security.core.usecase;

import com.sitepark.ies.security.core.domain.value.WebAuthnAssertionCredential;
import com.sitepark.ies.security.core.domain.value.WebAuthnAssertionFinishResult;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.security.core.port.WebAuthnProvider;
import com.sitepark.ies.security.core.usecase.authentication.AuthenticationResult;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;
import java.util.Optional;

public class FinishWebAuthnAssertionUseCase {

  private final UserService userService;
  private final WebAuthnProvider webAuthnProvider;

  @Inject
  protected FinishWebAuthnAssertionUseCase(
      UserService userService, WebAuthnProvider webAuthnProvider) {
    this.userService = userService;
    this.webAuthnProvider = webAuthnProvider;
  }

  public AuthenticationResult finishWebAuthnAssertion(WebAuthnAssertionCredential credential) {

    WebAuthnAssertionFinishResult result =
        this.webAuthnProvider.finishAssertion(credential.publicKeyCredentialJson());

    Optional<User> userOpt = this.userService.findByUsername(result.username());
    if (userOpt.isEmpty()) {
      return AuthenticationResult.failure();
    }

    if (result.success()) {
      return AuthenticationResult.success(userOpt.get(), result.applicationName());
    }

    return AuthenticationResult.failure();
  }
}

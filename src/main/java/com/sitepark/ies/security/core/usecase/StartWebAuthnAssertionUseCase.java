package com.sitepark.ies.security.core.usecase;

import com.sitepark.ies.security.core.port.WebAuthnProvider;
import com.sitepark.ies.security.core.usecase.authentication.WebAuthnAssertionCommand;
import jakarta.inject.Inject;
import java.net.URI;
import java.net.URISyntaxException;

public class StartWebAuthnAssertionUseCase {

  private final WebAuthnProvider webAuthnProvider;

  @Inject
  protected StartWebAuthnAssertionUseCase(WebAuthnProvider webAuthnProvider) {
    this.webAuthnProvider = webAuthnProvider;
  }

  public String startWebAuthnAssertion(WebAuthnAssertionCommand command) {

    URI origin;
    try {
      origin = new URI(command.origin());
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Invalid origin: " + command.origin(), e);
    }

    return this.webAuthnProvider.startAssertion(origin, command.applicationName());
  }
}

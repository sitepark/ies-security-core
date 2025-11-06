package com.sitepark.ies.security.core.usecase.webauthn;

import com.sitepark.ies.security.core.port.WebAuthnProvider;
import jakarta.inject.Inject;
import java.net.URI;
import java.net.URISyntaxException;

public class StartWebAuthnAssertionUseCase {

  private final WebAuthnProvider webAuthnProvider;

  @Inject
  protected StartWebAuthnAssertionUseCase(WebAuthnProvider webAuthnProvider) {
    this.webAuthnProvider = webAuthnProvider;
  }

  public String startWebAuthnAssertion(WebAuthnAssertionRequest request) {

    URI origin;
    try {
      origin = new URI(request.origin());
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Invalid origin: " + request.origin(), e);
    }

    return this.webAuthnProvider.startAssertion(origin, request.applicationName());
  }
}

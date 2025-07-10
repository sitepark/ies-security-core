package com.sitepark.ies.security.core.usecase.webauthn;

import com.sitepark.ies.security.core.port.WebAuthnProvider;
import jakarta.inject.Inject;

public class FinishWebAuthnRegistrationUseCase {

  private final WebAuthnProvider webAuthnProvider;

  @Inject
  protected FinishWebAuthnRegistrationUseCase(WebAuthnProvider webAuthnProvider) {
    this.webAuthnProvider = webAuthnProvider;
  }

  public void finishWebAuthnRegistration(String publicKeyCredentialJson) {
    this.webAuthnProvider.finishRegistration(publicKeyCredentialJson);
  }
}

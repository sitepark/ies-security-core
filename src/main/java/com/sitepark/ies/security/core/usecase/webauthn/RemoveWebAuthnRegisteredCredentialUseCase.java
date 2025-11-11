package com.sitepark.ies.security.core.usecase.webauthn;

import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.port.WebAuthnProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import jakarta.inject.Inject;

public class RemoveWebAuthnRegisteredCredentialUseCase {

  private final AccessControl accessControl;
  private final WebAuthnProvider webAuthnProvider;

  @Inject
  protected RemoveWebAuthnRegisteredCredentialUseCase(
      AccessControl accessControl, WebAuthnProvider webAuthnProvider) {
    this.accessControl = accessControl;
    this.webAuthnProvider = webAuthnProvider;
  }

  public void removeWebAuthnRegisteredCredential(String id) {

    if (!this.accessControl.isWebAuthnRemoveRegisteredCredentialsAllowed(id)) {
      throw new AccessDeniedException(
          "Remove webAuthn registration credentials with id " + id + " not allowed");
    }

    this.webAuthnProvider.removeRegisteredCredential(id);
  }
}

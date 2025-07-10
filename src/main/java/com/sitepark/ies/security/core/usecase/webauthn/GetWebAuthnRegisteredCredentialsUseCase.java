package com.sitepark.ies.security.core.usecase.webauthn;

import com.sitepark.ies.security.core.domain.entity.WebAuthnRegisteredCredential;
import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.WebAuthnProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import jakarta.inject.Inject;
import java.util.List;

public class GetWebAuthnRegisteredCredentialsUseCase {

  private final AccessControl accessControl;
  private final WebAuthnProvider webAuthnProvider;

  @Inject
  protected GetWebAuthnRegisteredCredentialsUseCase(
      AccessControl accessControl, WebAuthnProvider webAuthnProvider) {
    this.accessControl = accessControl;
    this.webAuthnProvider = webAuthnProvider;
  }

  public List<WebAuthnRegisteredCredential> getWebAuthnRegisteredCredentials(String userId) {

    if (!this.accessControl.isWebAuthnGetRegisteredCredentialsAllowed(userId)) {
      throw new AccessDeniedException(
          "Get webAuthn registration credentials from user " + userId + " not allowed");
    }

    return this.webAuthnProvider.findRegisteredCredentialByUserId(userId);
  }
}

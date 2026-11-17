package com.sitepark.ies.security.core.usecase.webauthn;

import com.sitepark.ies.security.core.domain.service.AuthenticationPolicyService;
import com.sitepark.ies.security.core.domain.value.AuthFactorType;
import com.sitepark.ies.security.core.port.WebAuthnProvider;
import jakarta.inject.Inject;
import java.net.URI;
import java.net.URISyntaxException;

public class StartWebAuthnAssertionUseCase {

  private final WebAuthnProvider webAuthnProvider;

  private final AuthenticationPolicyService policyService;

  @Inject
  protected StartWebAuthnAssertionUseCase(
      WebAuthnProvider webAuthnProvider, AuthenticationPolicyService policyService) {
    this.policyService = policyService;
    this.webAuthnProvider = webAuthnProvider;
  }

  public String startWebAuthnAssertion(WebAuthnAssertionRequest request) {
    this.policyService.requireFactorAllowed(AuthFactorType.PASSKEY);

    URI origin;
    try {
      origin = new URI(request.origin());
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Invalid origin: " + request.origin(), e);
    }

    return this.webAuthnProvider.startAssertion(origin, request.applicationName());
  }
}

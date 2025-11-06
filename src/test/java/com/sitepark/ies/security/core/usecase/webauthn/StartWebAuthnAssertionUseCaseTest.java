package com.sitepark.ies.security.core.usecase.webauthn;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.sitepark.ies.security.core.port.WebAuthnProvider;
import java.net.URI;
import java.net.URISyntaxException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class StartWebAuthnAssertionUseCaseTest {

  private WebAuthnProvider webAuthnProvider;

  private StartWebAuthnAssertionUseCase useCase;

  @BeforeEach
  void setUp() {
    this.webAuthnProvider = mock();
    this.useCase = new StartWebAuthnAssertionUseCase(webAuthnProvider);
  }

  @Test
  void testInvalidOrigin() {
    String invalidOrigin = ":htp//invalid-origin";
    WebAuthnAssertionRequest command = new WebAuthnAssertionRequest(invalidOrigin, "Test App");

    assertThrows(IllegalArgumentException.class, () -> useCase.startWebAuthnAssertion(command));
  }

  @Test
  void testStartWebAuthnAssertion() throws URISyntaxException {
    WebAuthnAssertionRequest command =
        new WebAuthnAssertionRequest("https://valid-origin.com", "Test App");
    this.useCase.startWebAuthnAssertion(command);
    verify(this.webAuthnProvider).startAssertion(new URI("https://valid-origin.com"), "Test App");
  }
}

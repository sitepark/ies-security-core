package com.sitepark.ies.security.core.usecase.webauthn;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.sitepark.ies.security.core.port.WebAuthnProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class FinishWebAuthnRegistrationUseCaseTest {

  private WebAuthnProvider webAuthnProvider;

  private FinishWebAuthnRegistrationUseCase useCase;

  @BeforeEach
  void setUp() {
    this.webAuthnProvider = mock();

    this.useCase = new FinishWebAuthnRegistrationUseCase(webAuthnProvider);
  }

  @Test
  void testFinishWebAuthnRegistration() {
    this.useCase.finishWebAuthnRegistration("key");
    verify(this.webAuthnProvider).finishRegistration("key");
  }
}

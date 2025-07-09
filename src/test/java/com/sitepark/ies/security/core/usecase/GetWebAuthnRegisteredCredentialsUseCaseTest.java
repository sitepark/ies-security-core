package com.sitepark.ies.security.core.usecase;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.entity.WebAuthnRegisteredCredential;
import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.WebAuthnProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class GetWebAuthnRegisteredCredentialsUseCaseTest {

  private AccessControl accessControl;
  private WebAuthnProvider webAuthnProvider;
  private GetWebAuthnRegisteredCredentialsUseCase useCase;

  @BeforeEach
  void setUp() {
    this.accessControl = mock();
    this.webAuthnProvider = mock();
    this.useCase = new GetWebAuthnRegisteredCredentialsUseCase(accessControl, webAuthnProvider);
  }

  @Test
  void testAccessControl() {
    when(accessControl.isWebAuthnGetRegisteredCredentialsAllowed(any())).thenReturn(false);
    assertThrows(
        AccessDeniedException.class,
        () -> {
          useCase.getWebAuthnRegisteredCredentials("123");
        });
  }

  @Test
  void testGet() {
    when(accessControl.isWebAuthnGetRegisteredCredentialsAllowed(any())).thenReturn(true);

    WebAuthnRegisteredCredential credential1 = mock();
    WebAuthnRegisteredCredential credential2 = mock();

    when(webAuthnProvider.findRegisteredCredentialByUserId(any()))
        .thenReturn(List.of(credential1, credential2));

    List<WebAuthnRegisteredCredential> credentials =
        useCase.getWebAuthnRegisteredCredentials("123");

    List<WebAuthnRegisteredCredential> expected = List.of(credential1, credential2);
    assertEquals(expected, credentials, "Expected credentials to match");
  }
}

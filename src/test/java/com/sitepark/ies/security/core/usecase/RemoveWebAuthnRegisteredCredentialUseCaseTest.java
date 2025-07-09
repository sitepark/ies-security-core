package com.sitepark.ies.security.core.usecase;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.WebAuthnProvider;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RemoveWebAuthnRegisteredCredentialUseCaseTest {
  private AccessControl accessControl;
  private WebAuthnProvider webAuthnProvider;
  private RemoveWebAuthnRegisteredCredentialUseCase useCase;

  @BeforeEach
  void setUp() {
    this.accessControl = mock();
    this.webAuthnProvider = mock();
    this.useCase = new RemoveWebAuthnRegisteredCredentialUseCase(accessControl, webAuthnProvider);
  }

  @Test
  void testAccessControl() {
    when(this.accessControl.isWebAuthnRemoveRegisteredCredentialsAllowed(any())).thenReturn(false);
    assertThrows(
        AccessDeniedException.class,
        () -> {
          useCase.removeWebAuthnRegisteredCredential("123");
        });
  }

  @Test
  void testRemoveWebAuthnRegisteredCredential() {
    when(this.accessControl.isWebAuthnRemoveRegisteredCredentialsAllowed(any())).thenReturn(true);

    String userId = "123";
    useCase.removeWebAuthnRegisteredCredential(userId);
    verify(this.webAuthnProvider).removeRegisteredCredential(userId);
  }
}

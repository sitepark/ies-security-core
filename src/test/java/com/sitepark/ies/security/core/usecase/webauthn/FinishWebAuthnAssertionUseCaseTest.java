package com.sitepark.ies.security.core.usecase.webauthn;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.value.AuthenticationResult;
import com.sitepark.ies.security.core.domain.value.WebAuthnAssertionFinishResult;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.security.core.port.WebAuthnProvider;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class FinishWebAuthnAssertionUseCaseTest {

  private UserService userService;
  private WebAuthnProvider webAuthnProvider;
  private FinishWebAuthnAssertionUseCase useCase;

  @BeforeEach
  void setUp() {
    this.userService = mock();
    this.webAuthnProvider = mock();
    this.useCase = new FinishWebAuthnAssertionUseCase(userService, webAuthnProvider);
  }

  @Test
  void testUserNotFound() {

    WebAuthnAssertionFinishResult authnResult =
        new WebAuthnAssertionFinishResult(true, true, "Test App", "testUser");

    when(this.webAuthnProvider.finishAssertion(any())).thenReturn(authnResult);
    when(this.userService.findByUsername(Mockito.anyString())).thenReturn(Optional.empty());

    AuthenticationResult result = this.useCase.finishWebAuthnAssertion("publicKeyCredentialJson");

    assertEquals(AuthenticationResult.failure(), result, "Expected failure when user not found");
  }

  @Test
  void testSuccessfulAssertion() {

    WebAuthnAssertionFinishResult authnResult =
        new WebAuthnAssertionFinishResult(true, true, "Test App", "testUser");

    when(this.webAuthnProvider.finishAssertion(any())).thenReturn(authnResult);
    User user = User.builder().id("123").username("peterpan").lastName("Pan").build();
    when(this.userService.findByUsername(Mockito.anyString())).thenReturn(Optional.of(user));

    AuthenticationResult result = this.useCase.finishWebAuthnAssertion("publicKeyCredentialJson");

    AuthenticationResult expected = AuthenticationResult.success(user, "Test App");

    assertEquals(expected, result, "Expected successful authentication result");
  }

  @Test
  void testFailedAssertion() {

    WebAuthnAssertionFinishResult authnResult =
        new WebAuthnAssertionFinishResult(false, false, "Test App", "testUser");

    when(this.webAuthnProvider.finishAssertion(any())).thenReturn(authnResult);
    User user = User.builder().id("123").username("peterpan").lastName("Pan").build();
    when(this.userService.findByUsername(Mockito.anyString())).thenReturn(Optional.of(user));

    AuthenticationResult result = this.useCase.finishWebAuthnAssertion("publicKeyCredentialJson");

    assertEquals(AuthenticationResult.failure(), result, "Expected failure on assertion");
  }
}

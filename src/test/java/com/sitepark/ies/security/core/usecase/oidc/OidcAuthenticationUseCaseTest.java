package com.sitepark.ies.security.core.usecase.oidc;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.value.AuthenticationResult;
import com.sitepark.ies.security.core.domain.value.OidcUser;
import com.sitepark.ies.security.core.port.OidcAuthenticator;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.AuthProviderType;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OidcAuthenticationUseCaseTest {
  private OidcAuthenticator oidcAuthenticator;
  private UserService userService;
  private OidcAuthenticationUseCase useCase;

  @BeforeEach
  void setUp() {
    this.oidcAuthenticator = mock();
    this.userService = mock();
    this.useCase = new OidcAuthenticationUseCase(oidcAuthenticator, userService);
  }

  @Test
  void testAuthenticationFailure() {
    when(this.oidcAuthenticator.authenticate(any(), any(), any())).thenReturn(null);

    AuthenticationResult result =
        this.useCase.oidcAuthentication(AuthProviderType.GOOGLE, "Test App", "code");

    assertEquals(AuthenticationResult.failure(), result, "Expected failure on authentication");
  }

  @Test
  void testSynchronousAuthenticationFailure() {

    OidcUser oidcUser = new OidcUser("123", "Peter Pan", "Peter", "Pan", "peterpan@neverland.com");
    when(this.oidcAuthenticator.authenticate(any(), any(), any())).thenReturn(oidcUser);

    when(this.userService.syncAuthenticatedUser(any(), any())).thenReturn(Optional.empty());
    AuthenticationResult result =
        this.useCase.oidcAuthentication(AuthProviderType.GOOGLE, "Test App", "code");

    assertEquals(AuthenticationResult.failure(), result, "Expected failure on sync authentication");
  }

  @Test
  void testSuccessfulAuthentication() {
    OidcUser oidcUser = new OidcUser("123", "Peter Pan", "Peter", "Pan", "peterpan@neverland.com");
    when(this.oidcAuthenticator.authenticate(any(), any(), any())).thenReturn(oidcUser);

    User user =
        User.builder()
            .id("123")
            .username("peterpan@neverland.com")
            .firstName("Peter")
            .lastName("Pan")
            .email("peterpan@neverland.com")
            .build();
    when(this.userService.syncAuthenticatedUser(any(), any())).thenReturn(Optional.of(user));
    AuthenticationResult result =
        this.useCase.oidcAuthentication(AuthProviderType.GOOGLE, "Test App", "code");
    AuthenticationResult expected = AuthenticationResult.success(user, "Test App");
    assertEquals(expected, result, "Expected successful authentication result");
  }
}

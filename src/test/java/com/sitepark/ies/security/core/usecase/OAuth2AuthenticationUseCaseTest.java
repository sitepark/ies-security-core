package com.sitepark.ies.security.core.usecase;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.value.OAuth2User;
import com.sitepark.ies.security.core.port.OAuth2Authenticator;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.security.core.usecase.authentication.AuthenticationResult;
import com.sitepark.ies.sharedkernel.security.AuthProviderType;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OAuth2AuthenticationUseCaseTest {
  private OAuth2Authenticator oAuth2Authenticator;
  private UserService userService;
  private OAuth2AuthenticationUseCase useCase;

  @BeforeEach
  void setUp() {
    this.oAuth2Authenticator = mock();
    this.userService = mock();
    this.useCase = new OAuth2AuthenticationUseCase(oAuth2Authenticator, userService);
  }

  @Test
  void testAuthenticationFailure() {
    when(this.oAuth2Authenticator.authenticate(any(), any(), any())).thenReturn(null);

    AuthenticationResult result =
        this.useCase.oauth2Authentication(AuthProviderType.GOOGLE, "Test App", "code");

    assertEquals(AuthenticationResult.failure(), result, "Expected failure on authentication");
  }

  @Test
  void testSynchronousAuthenticationFailure() {

    OAuth2User oAuth2User =
        new OAuth2User("123", "Peter Pan", "Peter", "Pan", "peterpan@neverland.com");
    when(this.oAuth2Authenticator.authenticate(any(), any(), any())).thenReturn(oAuth2User);

    when(this.userService.syncAuthenticatedUser(any(), any())).thenReturn(Optional.empty());
    AuthenticationResult result =
        this.useCase.oauth2Authentication(AuthProviderType.GOOGLE, "Test App", "code");

    assertEquals(AuthenticationResult.failure(), result, "Expected failure on sync authentication");
  }

  @Test
  void testSuccessfulAuthentication() {
    OAuth2User oAuth2User =
        new OAuth2User("123", "Peter Pan", "Peter", "Pan", "peterpan@neverland.com");
    when(this.oAuth2Authenticator.authenticate(any(), any(), any())).thenReturn(oAuth2User);

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
        this.useCase.oauth2Authentication(AuthProviderType.GOOGLE, "Test App", "code");
    AuthenticationResult expected = AuthenticationResult.success(user, "Test App");
    assertEquals(expected, result, "Expected successful authentication result");
  }
}

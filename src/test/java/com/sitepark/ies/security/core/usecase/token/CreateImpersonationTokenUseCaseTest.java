package com.sitepark.ies.security.core.usecase.token;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.exception.InvalidAccessTokenException;
import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class CreateImpersonationTokenUseCaseTest {

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testAccessDenied() {

    AccessTokenRepository accessTokenRepository = mock();
    AccessControl accessControl = mock(AccessControl.class);
    when(accessControl.isImpersonationTokensManageable()).thenReturn(false);
    UserService userService = mock(UserService.class);

    var createImpersonationToken =
        new CreateImpersonationTokenUserCase(accessTokenRepository, accessControl, userService);

    assertThrows(
        AccessDeniedException.class,
        () -> {
          createImpersonationToken.createImpersonationToken(
              new CreateImpersonationTokenRequest("123", "Test Token", null));
        });

    verify(accessControl).isImpersonationTokensManageable();
  }

  @Test
  void testUserNotFound() {

    AccessTokenRepository accessTokenRepository = mock();
    AccessControl accessControl = mock(AccessControl.class);
    when(accessControl.isImpersonationTokensManageable()).thenReturn(true);
    UserService userService = mock(UserService.class);
    when(userService.findById(anyString())).thenReturn(Optional.empty());

    var createImpersonationToken =
        new CreateImpersonationTokenUserCase(accessTokenRepository, accessControl, userService);

    assertThrows(
        InvalidAccessTokenException.class,
        () -> {
          createImpersonationToken.createImpersonationToken(
              new CreateImpersonationTokenRequest("123", "Test Token", null));
        });
  }

  @Test
  void testCreate() {

    AccessTokenRepository accessTokenRepository = mock();
    AccessControl accessControl = mock(AccessControl.class);
    when(accessControl.isImpersonationTokensManageable()).thenReturn(true);
    UserService userService = mock(UserService.class);
    User user = mock(User.class);
    when(userService.findById(anyString())).thenReturn(Optional.of(user));

    var createImpersonationToken =
        new CreateImpersonationTokenUserCase(accessTokenRepository, accessControl, userService);

    createImpersonationToken.createImpersonationToken(
        new CreateImpersonationTokenRequest("123", "Test Token", null));

    verify(accessTokenRepository).create(any());
  }
}

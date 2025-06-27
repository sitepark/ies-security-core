package com.sitepark.ies.security.core.usecase;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import com.sitepark.ies.security.core.domain.exception.InvalidAccessTokenException;
import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class CreateImpersonationTokenTest {

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testAccessDenied() {

    AccessTokenRepository accessTokenRepository = mock();
    AccessControl accessControl = mock(AccessControl.class);
    when(accessControl.isImpersonationTokensManageable()).thenReturn(false);
    UserService userService = mock(UserService.class);

    AccessToken accessToken = AccessToken.builder().user("123").name("Test Token").build();

    var createImpersonationToken =
        new CreateImpersonationToken(accessTokenRepository, accessControl, userService);

    assertThrows(
        AccessDeniedException.class,
        () -> {
          createImpersonationToken.createPersonalAccessToken(accessToken);
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

    AccessToken accessToken = AccessToken.builder().user("123").name("Test Token").build();

    var createImpersonationToken =
        new CreateImpersonationToken(accessTokenRepository, accessControl, userService);

    assertThrows(
        InvalidAccessTokenException.class,
        () -> {
          createImpersonationToken.createPersonalAccessToken(accessToken);
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

    AccessToken accessToken = AccessToken.builder().user("123").name("Test Token").build();

    var createImpersonationToken =
        new CreateImpersonationToken(accessTokenRepository, accessControl, userService);

    createImpersonationToken.createPersonalAccessToken(accessToken);

    verify(accessTokenRepository).create(any());
  }
}

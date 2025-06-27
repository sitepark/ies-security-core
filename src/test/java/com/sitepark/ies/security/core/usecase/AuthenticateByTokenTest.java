package com.sitepark.ies.security.core.usecase;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import com.sitepark.ies.security.core.domain.exception.AccessTokenExpiredException;
import com.sitepark.ies.security.core.domain.exception.AccessTokenNotActiveException;
import com.sitepark.ies.security.core.domain.exception.AccessTokenRevokedException;
import com.sitepark.ies.security.core.domain.exception.InvalidAccessTokenException;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.AuthFactor;
import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.User;
import java.time.OffsetDateTime;
import java.util.Optional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class AuthenticateByTokenTest {

  private static final String TOKEN_NAME = "Test Token";

  private static final String TOKEN_STRING = "abc";

  @Test
  void testTokenNotFound() {

    AccessTokenRepository accessTokenRepository = mock();
    when(accessTokenRepository.getByToken(any())).thenReturn(Optional.empty());
    UserService userService = mock();

    var authenticateByToken = new AuthenticateByToken(accessTokenRepository, userService);

    assertThrows(
        InvalidAccessTokenException.class,
        () -> {
          authenticateByToken.authenticateByToken(TOKEN_STRING);
        });
  }

  @Test
  void testTokenNotActive() {

    AccessToken accessToken =
        AccessToken.builder().id("1").name(TOKEN_NAME).user("2").active(false).build();

    AccessTokenRepository accessTokenRepository = mock();
    when(accessTokenRepository.getByToken(any())).thenReturn(Optional.of(accessToken));
    UserService userService = mock();

    var authenticateByToken = new AuthenticateByToken(accessTokenRepository, userService);

    assertThrows(
        AccessTokenNotActiveException.class,
        () -> {
          authenticateByToken.authenticateByToken(TOKEN_STRING);
        });
  }

  @Test
  void testTokenRevoked() {

    AccessToken accessToken =
        AccessToken.builder().id("1").name(TOKEN_NAME).user("2").revoked(true).build();

    AccessTokenRepository accessTokenRepository = mock();
    when(accessTokenRepository.getByToken(any())).thenReturn(Optional.of(accessToken));
    UserService userService = mock();

    var authenticateByToken = new AuthenticateByToken(accessTokenRepository, userService);

    assertThrows(
        AccessTokenRevokedException.class,
        () -> {
          authenticateByToken.authenticateByToken("abc");
        });
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testTokenExpired() {

    OffsetDateTime expiredAt = OffsetDateTime.now().minusDays(1);

    AccessToken accessToken =
        AccessToken.builder().id("1").name(TOKEN_NAME).user("2").expiresAt(expiredAt).build();

    AccessTokenRepository accessTokenRepository = mock();
    when(accessTokenRepository.getByToken(any())).thenReturn(Optional.of(accessToken));
    UserService userService = mock();

    var authenticateByToken = new AuthenticateByToken(accessTokenRepository, userService);

    AccessTokenExpiredException e =
        assertThrows(
            AccessTokenExpiredException.class,
            () -> {
              authenticateByToken.authenticateByToken(TOKEN_STRING);
            });
    assertNotNull(e.getExpiredAt(), "expiredAt expected");
    assertNotNull(e.getMessage(), "message expected");
  }

  @Test
  void testUserNotFound() {

    AccessToken accessToken = AccessToken.builder().id("1").name(TOKEN_NAME).user("2").build();

    AccessTokenRepository accessTokenRepository = mock();
    when(accessTokenRepository.getByToken(any())).thenReturn(Optional.of(accessToken));

    UserService userService = mock();

    when(userService.findById(anyString())).thenReturn(Optional.empty());

    var authenticateByToken = new AuthenticateByToken(accessTokenRepository, userService);

    assertThrows(
        InvalidAccessTokenException.class,
        () -> {
          authenticateByToken.authenticateByToken(TOKEN_STRING);
        });
  }

  @Test
  void testValidAutentification() {

    AccessToken accessToken = AccessToken.builder().id("1").name(TOKEN_NAME).user("2").build();

    User user =
        new User(
            "1",
            "test",
            "First",
            "Last",
            "test@test.com",
            new AuthMethod[] {},
            new AuthFactor[] {},
            null);

    AccessTokenRepository accessTokenRepository = mock();
    when(accessTokenRepository.getByToken(any())).thenReturn(Optional.of(accessToken));

    UserService userService = mock();

    when(userService.findById(anyString())).thenReturn(Optional.of(user));

    var authenticateByToken = new AuthenticateByToken(accessTokenRepository, userService);

    User authenticatedUser = authenticateByToken.authenticateByToken(TOKEN_STRING);
    Assertions.assertEquals(user.getId(), authenticatedUser.getId(), "unexpected user");
  }

  @Test
  void testValidAutentificationWithExpiredDate() {

    OffsetDateTime expiredAt = OffsetDateTime.now().plusDays(1);

    AccessToken accessToken =
        AccessToken.builder().id("1").name(TOKEN_NAME).expiresAt(expiredAt).user("2").build();

    User user =
        new User(
            "1",
            "test",
            "First",
            "Last",
            "test@test.com",
            new AuthMethod[] {},
            new AuthFactor[] {},
            null);

    AccessTokenRepository accessTokenRepository = mock();
    when(accessTokenRepository.getByToken(any())).thenReturn(Optional.of(accessToken));

    UserService userService = mock();

    when(userService.findById(anyString())).thenReturn(Optional.of(user));

    var authenticateByToken = new AuthenticateByToken(accessTokenRepository, userService);

    User authenticatedUser = authenticateByToken.authenticateByToken(TOKEN_STRING);
    Assertions.assertEquals(user.getId(), authenticatedUser.getId(), "unexpected user");
  }
}

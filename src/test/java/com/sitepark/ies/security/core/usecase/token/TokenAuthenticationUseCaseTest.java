package com.sitepark.ies.security.core.usecase.token;

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
import com.sitepark.ies.security.core.domain.value.TokenType;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.security.core.port.PermissionLoader;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.Identity;
import com.sitepark.ies.sharedkernel.security.User;
import com.sitepark.ies.sharedkernel.security.UserBasedAuthentication;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TokenAuthenticationUseCaseTest {

  private static final String TOKEN_NAME = "Test Token";

  private static final String TOKEN_STRING = "abc";

  private AccessTokenRepository accessTokenRepository;

  private UserService userService;

  private Clock fixedClock;

  private TokenAuthenticationUseCase useCase;

  @BeforeEach
  void setUp() {
    this.accessTokenRepository = mock();
    PermissionLoader permissionLoader = mock();
    this.userService = mock();
    OffsetDateTime fixedTime = OffsetDateTime.parse("2024-06-13T12:00:00+02:00");
    this.fixedClock = Clock.fixed(fixedTime.toInstant(), fixedTime.getOffset());

    this.useCase =
        new TokenAuthenticationUseCase(
            this.fixedClock, accessTokenRepository, permissionLoader, this.userService);
  }

  @Test
  void testTokenNotFound() {

    when(this.accessTokenRepository.getByToken(any())).thenReturn(Optional.empty());

    assertThrows(
        InvalidAccessTokenException.class,
        () -> {
          useCase.authenticateByToken(TOKEN_STRING);
        });
  }

  @Test
  void testTokenNotActive() {

    AccessToken accessToken =
        AccessToken.builder()
            .id("1")
            .name(TOKEN_NAME)
            .userId("2")
            .tokenType(TokenType.IMPERSONATION)
            .active(false)
            .build();

    when(this.accessTokenRepository.getByToken(any())).thenReturn(Optional.of(accessToken));

    assertThrows(
        AccessTokenNotActiveException.class,
        () -> {
          this.useCase.authenticateByToken(TOKEN_STRING);
        });
  }

  @Test
  void testTokenRevoked() {

    AccessToken accessToken =
        AccessToken.builder()
            .id("1")
            .name(TOKEN_NAME)
            .userId("2")
            .tokenType(TokenType.IMPERSONATION)
            .revoked(true)
            .build();

    when(this.accessTokenRepository.getByToken(any())).thenReturn(Optional.of(accessToken));

    assertThrows(
        AccessTokenRevokedException.class,
        () -> {
          this.useCase.authenticateByToken("abc");
        });
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testTokenExpired() {

    Instant expiredAt = Instant.now(this.fixedClock).minus(1, ChronoUnit.DAYS);

    AccessToken accessToken =
        AccessToken.builder()
            .id("1")
            .name(TOKEN_NAME)
            .userId("2")
            .tokenType(TokenType.IMPERSONATION)
            .expiresAt(expiredAt)
            .build();

    when(this.accessTokenRepository.getByToken(any())).thenReturn(Optional.of(accessToken));

    AccessTokenExpiredException e =
        assertThrows(
            AccessTokenExpiredException.class,
            () -> {
              this.useCase.authenticateByToken(TOKEN_STRING);
            });
    assertNotNull(e.getExpiredAt(), "expiredAt expected");
    assertNotNull(e.getMessage(), "message expected");
  }

  @Test
  void testUserNotFound() {

    AccessToken accessToken =
        AccessToken.builder()
            .id("1")
            .name(TOKEN_NAME)
            .userId("2")
            .tokenType(TokenType.IMPERSONATION)
            .build();

    when(this.accessTokenRepository.getByToken(any())).thenReturn(Optional.of(accessToken));
    when(this.userService.findById(anyString())).thenReturn(Optional.empty());

    assertThrows(
        InvalidAccessTokenException.class,
        () -> {
          this.useCase.authenticateByToken(TOKEN_STRING);
        });
  }

  @Test
  void testValidAutentification() {

    AccessToken accessToken =
        AccessToken.builder()
            .id("1")
            .name(TOKEN_NAME)
            .userId("2")
            .tokenType(TokenType.IMPERSONATION)
            .build();

    User user =
        User.builder()
            .id("1")
            .username("test")
            .identity(Identity.internal())
            .firstName("First")
            .lastName("Last")
            .email("test@test.com")
            .build();

    when(this.accessTokenRepository.getByToken(any())).thenReturn(Optional.of(accessToken));
    when(this.userService.findById(anyString())).thenReturn(Optional.of(user));

    UserBasedAuthentication authentication =
        (UserBasedAuthentication) this.useCase.authenticateByToken(TOKEN_STRING);
    Assertions.assertEquals(user.id(), authentication.user().id(), "unexpected user");
  }

  @Test
  void testValidAutentificationWithExpiredDate() {

    Instant expiredAt = Instant.now(this.fixedClock).plus(1, ChronoUnit.DAYS);

    AccessToken accessToken =
        AccessToken.builder()
            .id("1")
            .name(TOKEN_NAME)
            .expiresAt(expiredAt)
            .userId("2")
            .tokenType(TokenType.IMPERSONATION)
            .build();

    User user =
        User.builder()
            .id("1")
            .username("test")
            .identity(Identity.internal())
            .firstName("First")
            .lastName("Last")
            .email("test@test.com")
            .build();

    when(this.accessTokenRepository.getByToken(any())).thenReturn(Optional.of(accessToken));
    when(this.userService.findById(anyString())).thenReturn(Optional.of(user));

    UserBasedAuthentication authentication =
        (UserBasedAuthentication) this.useCase.authenticateByToken(TOKEN_STRING);
    Assertions.assertEquals(user.id(), authentication.user().id(), "unexpected user");
  }
}

package com.sitepark.ies.security.core.usecase.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import com.sitepark.ies.security.core.domain.exception.InvalidAccessTokenException;
import com.sitepark.ies.security.core.domain.value.TokenType;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.security.core.port.TokenService;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.Authentication;
import com.sitepark.ies.sharedkernel.security.User;
import com.sitepark.ies.sharedkernel.security.UserAuthentication;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CreatePrivateTokenUseCaseTest {

  private Authentication authentication;
  private AccessTokenRepository accessTokenRepository;
  private TokenService tokenService;
  private UserService userService;
  private final Clock fixedClock =
      Clock.fixed(Instant.parse("2025-06-30T10:00:00Z"), ZoneId.of("UTC"));

  private CreatePrivateTokenUserCase useCase;

  @BeforeEach
  void setUp() {
    this.authentication = mock(Authentication.class);
    this.accessTokenRepository = mock();
    this.tokenService = mock();
    this.userService = mock();

    this.useCase =
        new CreatePrivateTokenUserCase(
            () -> this.authentication,
            this.accessTokenRepository,
            this.tokenService,
            this.userService,
            this.fixedClock);
  }

  @Test
  void testAccessDeniedWhenNotUserAuthentication() {

    assertThrows(
        AccessDeniedException.class,
        () -> {
          this.useCase.createPrivateToken(new CreatePrivateTokenRequest("Test Token", null));
        },
        "Should throw AccessDeniedException when authentication is not UserAuthentication");
  }

  @Test
  void testUserNotFound() {

    UserAuthentication userAuthentication = mock(UserAuthentication.class);
    User user = mock(User.class);
    when(user.id()).thenReturn("123");
    when(userAuthentication.user()).thenReturn(user);
    when(this.userService.findById(anyString())).thenReturn(Optional.empty());

    CreatePrivateTokenUserCase useCase =
        new CreatePrivateTokenUserCase(
            () -> userAuthentication,
            this.accessTokenRepository,
            this.tokenService,
            this.userService,
            this.fixedClock);

    assertThrows(
        InvalidAccessTokenException.class,
        () -> {
          useCase.createPrivateToken(new CreatePrivateTokenRequest("Test Token", null));
        },
        "Should throw InvalidAccessTokenException when user is not found");
  }

  @Test
  void testVerifyUserServiceCalled() {

    UserAuthentication userAuthentication = mock(UserAuthentication.class);
    User user = mock(User.class);
    when(user.id()).thenReturn("123");
    when(userAuthentication.user()).thenReturn(user);
    when(this.userService.findById(anyString())).thenReturn(Optional.of(user));
    when(this.tokenService.generateToken()).thenReturn("generated-token");
    when(this.tokenService.digestToken(anyString())).thenReturn("digested-token");

    AccessToken createdToken =
        AccessToken.builder()
            .id("1")
            .userId("123")
            .name("Test Token")
            .createdAt(this.fixedClock.instant())
            .tokenType(TokenType.PRIVATE)
            .build();
    when(this.accessTokenRepository.create(any(), anyString())).thenReturn(createdToken);

    CreatePrivateTokenUserCase useCase =
        new CreatePrivateTokenUserCase(
            () -> userAuthentication,
            this.accessTokenRepository,
            this.tokenService,
            this.userService,
            this.fixedClock);

    useCase.createPrivateToken(new CreatePrivateTokenRequest("Test Token", null));

    verify(this.userService).findById("123");
  }

  @Test
  void testVerifyTokenGenerated() {

    UserAuthentication userAuthentication = mock(UserAuthentication.class);
    User user = mock(User.class);
    when(user.id()).thenReturn("123");
    when(userAuthentication.user()).thenReturn(user);
    when(this.userService.findById(anyString())).thenReturn(Optional.of(user));
    when(this.tokenService.generateToken()).thenReturn("generated-token");
    when(this.tokenService.digestToken(anyString())).thenReturn("digested-token");

    AccessToken createdToken =
        AccessToken.builder()
            .id("1")
            .userId("123")
            .name("Test Token")
            .createdAt(this.fixedClock.instant())
            .tokenType(TokenType.PRIVATE)
            .build();
    when(this.accessTokenRepository.create(any(), anyString())).thenReturn(createdToken);

    CreatePrivateTokenUserCase useCase =
        new CreatePrivateTokenUserCase(
            () -> userAuthentication,
            this.accessTokenRepository,
            this.tokenService,
            this.userService,
            this.fixedClock);

    useCase.createPrivateToken(new CreatePrivateTokenRequest("Test Token", null));

    verify(this.tokenService).generateToken();
  }

  @Test
  void testVerifyTokenDigested() {

    UserAuthentication userAuthentication = mock(UserAuthentication.class);
    User user = mock(User.class);
    when(user.id()).thenReturn("123");
    when(userAuthentication.user()).thenReturn(user);
    when(this.userService.findById(anyString())).thenReturn(Optional.of(user));
    when(this.tokenService.generateToken()).thenReturn("generated-token");
    when(this.tokenService.digestToken(anyString())).thenReturn("digested-token");

    AccessToken createdToken =
        AccessToken.builder()
            .id("1")
            .userId("123")
            .name("Test Token")
            .createdAt(this.fixedClock.instant())
            .tokenType(TokenType.PRIVATE)
            .build();
    when(this.accessTokenRepository.create(any(), anyString())).thenReturn(createdToken);

    CreatePrivateTokenUserCase useCase =
        new CreatePrivateTokenUserCase(
            () -> userAuthentication,
            this.accessTokenRepository,
            this.tokenService,
            this.userService,
            this.fixedClock);

    useCase.createPrivateToken(new CreatePrivateTokenRequest("Test Token", null));

    verify(this.tokenService).digestToken("generated-token");
  }

  @Test
  void testVerifyRepositoryCreateCalled() {

    UserAuthentication userAuthentication = mock(UserAuthentication.class);
    User user = mock(User.class);
    when(user.id()).thenReturn("123");
    when(userAuthentication.user()).thenReturn(user);
    when(this.userService.findById(anyString())).thenReturn(Optional.of(user));
    when(this.tokenService.generateToken()).thenReturn("generated-token");
    when(this.tokenService.digestToken(anyString())).thenReturn("digested-token");

    AccessToken createdToken =
        AccessToken.builder()
            .id("1")
            .userId("123")
            .name("Test Token")
            .createdAt(this.fixedClock.instant())
            .tokenType(TokenType.PRIVATE)
            .build();
    when(this.accessTokenRepository.create(any(), anyString())).thenReturn(createdToken);

    CreatePrivateTokenUserCase useCase =
        new CreatePrivateTokenUserCase(
            () -> userAuthentication,
            this.accessTokenRepository,
            this.tokenService,
            this.userService,
            this.fixedClock);

    useCase.createPrivateToken(new CreatePrivateTokenRequest("Test Token", null));

    verify(this.accessTokenRepository).create(any(), anyString());
  }

  @Test
  void testCreateTokenResultReturnsCorrectEntity() {

    UserAuthentication userAuthentication = mock(UserAuthentication.class);
    User user = mock(User.class);
    when(user.id()).thenReturn("123");
    when(userAuthentication.user()).thenReturn(user);
    when(this.userService.findById(anyString())).thenReturn(Optional.of(user));
    when(this.tokenService.generateToken()).thenReturn("generated-token");
    when(this.tokenService.digestToken(anyString())).thenReturn("digested-token");

    AccessToken createdToken =
        AccessToken.builder()
            .id("1")
            .userId("123")
            .name("Test Token")
            .createdAt(this.fixedClock.instant())
            .tokenType(TokenType.PRIVATE)
            .build();
    when(this.accessTokenRepository.create(any(), anyString())).thenReturn(createdToken);

    CreatePrivateTokenUserCase useCase =
        new CreatePrivateTokenUserCase(
            () -> userAuthentication,
            this.accessTokenRepository,
            this.tokenService,
            this.userService,
            this.fixedClock);

    CreateTokenResult result =
        useCase.createPrivateToken(new CreatePrivateTokenRequest("Test Token", null));

    assertEquals(
        createdToken,
        result.entity(),
        "CreateTokenResult should contain the created AccessToken entity");
  }

  @Test
  void testCreateTokenResultReturnsCorrectToken() {

    UserAuthentication userAuthentication = mock(UserAuthentication.class);
    User user = mock(User.class);
    when(user.id()).thenReturn("123");
    when(userAuthentication.user()).thenReturn(user);
    when(this.userService.findById(anyString())).thenReturn(Optional.of(user));
    when(this.tokenService.generateToken()).thenReturn("generated-token");
    when(this.tokenService.digestToken(anyString())).thenReturn("digested-token");

    AccessToken createdToken =
        AccessToken.builder()
            .id("1")
            .userId("123")
            .name("Test Token")
            .createdAt(this.fixedClock.instant())
            .tokenType(TokenType.PRIVATE)
            .build();
    when(this.accessTokenRepository.create(any(), anyString())).thenReturn(createdToken);

    CreatePrivateTokenUserCase useCase =
        new CreatePrivateTokenUserCase(
            () -> userAuthentication,
            this.accessTokenRepository,
            this.tokenService,
            this.userService,
            this.fixedClock);

    CreateTokenResult result =
        useCase.createPrivateToken(new CreatePrivateTokenRequest("Test Token", null));

    assertEquals(
        "generated-token",
        result.token(),
        "CreateTokenResult should contain the generated token string");
  }

  @Test
  void testCreateTokenWithExpirationDate() {

    UserAuthentication userAuthentication = mock(UserAuthentication.class);
    User user = mock(User.class);
    when(user.id()).thenReturn("123");
    when(userAuthentication.user()).thenReturn(user);
    when(this.userService.findById(anyString())).thenReturn(Optional.of(user));
    when(this.tokenService.generateToken()).thenReturn("generated-token");
    when(this.tokenService.digestToken(anyString())).thenReturn("digested-token");

    Instant expiresAt = Instant.parse("2025-12-31T23:59:59Z");
    AccessToken createdToken =
        AccessToken.builder()
            .id("1")
            .userId("123")
            .name("Test Token")
            .createdAt(this.fixedClock.instant())
            .expiresAt(expiresAt)
            .tokenType(TokenType.PRIVATE)
            .build();
    when(this.accessTokenRepository.create(any(), anyString())).thenReturn(createdToken);

    CreatePrivateTokenUserCase useCase =
        new CreatePrivateTokenUserCase(
            () -> userAuthentication,
            this.accessTokenRepository,
            this.tokenService,
            this.userService,
            this.fixedClock);

    useCase.createPrivateToken(new CreatePrivateTokenRequest("Test Token", expiresAt));

    verify(this.accessTokenRepository).create(any(), anyString());
  }
}

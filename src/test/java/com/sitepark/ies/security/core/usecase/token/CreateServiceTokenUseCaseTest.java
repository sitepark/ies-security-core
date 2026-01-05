package com.sitepark.ies.security.core.usecase.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.value.TokenType;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.security.core.port.TokenService;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.Permission;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CreateServiceTokenUseCaseTest {

  private AccessTokenRepository accessTokenRepository;
  private AccessControl accessControl;
  private TokenService tokenService;
  private final Clock fixedClock =
      Clock.fixed(Instant.parse("2025-06-30T10:00:00Z"), ZoneId.of("UTC"));

  private CreateServiceTokenUserCase useCase;

  @BeforeEach
  void setUp() {
    this.accessTokenRepository = mock();
    this.accessControl = mock();
    this.tokenService = mock();
    UserService userService = mock();

    this.useCase =
        new CreateServiceTokenUserCase(
            this.accessTokenRepository,
            this.accessControl,
            this.tokenService,
            userService,
            this.fixedClock);
  }

  @Test
  void testAccessDenied() {

    when(this.accessControl.isImpersonationTokensManageable()).thenReturn(false);

    assertThrows(
        AccessDeniedException.class,
        () -> {
          this.useCase.createServiceToken(
              new CreateServiceTokenRequest("Test Token", List.of(), null));
        },
        "Should throw AccessDeniedException when user is not allowed to manage impersonation"
            + " tokens");
  }

  @Test
  void testVerifyAccessControlCalled() {

    when(this.accessControl.isImpersonationTokensManageable()).thenReturn(true);
    when(this.tokenService.generateToken()).thenReturn("generated-token");
    when(this.tokenService.digestToken(anyString())).thenReturn("digested-token");

    AccessToken createdToken =
        AccessToken.builder()
            .id("1")
            .name("Test Token")
            .createdAt(this.fixedClock.instant())
            .tokenType(TokenType.SERVICE)
            .build();
    when(this.accessTokenRepository.create(any(), anyString())).thenReturn(createdToken);

    this.useCase.createServiceToken(new CreateServiceTokenRequest("Test Token", List.of(), null));

    verify(this.accessControl).isImpersonationTokensManageable();
  }

  @Test
  void testVerifyTokenGenerated() {

    when(this.accessControl.isImpersonationTokensManageable()).thenReturn(true);
    when(this.tokenService.generateToken()).thenReturn("generated-token");
    when(this.tokenService.digestToken(anyString())).thenReturn("digested-token");

    AccessToken createdToken =
        AccessToken.builder()
            .id("1")
            .name("Test Token")
            .createdAt(this.fixedClock.instant())
            .tokenType(TokenType.SERVICE)
            .build();
    when(this.accessTokenRepository.create(any(), anyString())).thenReturn(createdToken);

    this.useCase.createServiceToken(new CreateServiceTokenRequest("Test Token", List.of(), null));

    verify(this.tokenService).generateToken();
  }

  @Test
  void testVerifyTokenDigested() {

    when(this.accessControl.isImpersonationTokensManageable()).thenReturn(true);
    when(this.tokenService.generateToken()).thenReturn("generated-token");
    when(this.tokenService.digestToken(anyString())).thenReturn("digested-token");

    AccessToken createdToken =
        AccessToken.builder()
            .id("1")
            .name("Test Token")
            .createdAt(this.fixedClock.instant())
            .tokenType(TokenType.SERVICE)
            .build();
    when(this.accessTokenRepository.create(any(), anyString())).thenReturn(createdToken);

    this.useCase.createServiceToken(new CreateServiceTokenRequest("Test Token", List.of(), null));

    verify(this.tokenService).digestToken("generated-token");
  }

  @Test
  void testVerifyRepositoryCreateCalled() {

    when(this.accessControl.isImpersonationTokensManageable()).thenReturn(true);
    when(this.tokenService.generateToken()).thenReturn("generated-token");
    when(this.tokenService.digestToken(anyString())).thenReturn("digested-token");

    AccessToken createdToken =
        AccessToken.builder()
            .id("1")
            .name("Test Token")
            .createdAt(this.fixedClock.instant())
            .tokenType(TokenType.SERVICE)
            .build();
    when(this.accessTokenRepository.create(any(), anyString())).thenReturn(createdToken);

    this.useCase.createServiceToken(new CreateServiceTokenRequest("Test Token", List.of(), null));

    verify(this.accessTokenRepository).create(any(), anyString());
  }

  @Test
  void testCreateTokenResultReturnsCorrectEntity() {

    when(this.accessControl.isImpersonationTokensManageable()).thenReturn(true);
    when(this.tokenService.generateToken()).thenReturn("generated-token");
    when(this.tokenService.digestToken(anyString())).thenReturn("digested-token");

    AccessToken createdToken =
        AccessToken.builder()
            .id("1")
            .name("Test Token")
            .createdAt(this.fixedClock.instant())
            .tokenType(TokenType.SERVICE)
            .build();
    when(this.accessTokenRepository.create(any(), anyString())).thenReturn(createdToken);

    CreateTokenResult result =
        this.useCase.createServiceToken(
            new CreateServiceTokenRequest("Test Token", List.of(), null));

    assertEquals(
        createdToken,
        result.entity(),
        "CreateTokenResult should contain the created AccessToken entity");
  }

  @Test
  void testCreateTokenResultReturnsCorrectToken() {

    when(this.accessControl.isImpersonationTokensManageable()).thenReturn(true);
    when(this.tokenService.generateToken()).thenReturn("generated-token");
    when(this.tokenService.digestToken(anyString())).thenReturn("digested-token");

    AccessToken createdToken =
        AccessToken.builder()
            .id("1")
            .name("Test Token")
            .createdAt(this.fixedClock.instant())
            .tokenType(TokenType.SERVICE)
            .build();
    when(this.accessTokenRepository.create(any(), anyString())).thenReturn(createdToken);

    CreateTokenResult result =
        this.useCase.createServiceToken(
            new CreateServiceTokenRequest("Test Token", List.of(), null));

    assertEquals(
        "generated-token",
        result.token(),
        "CreateTokenResult should contain the generated token string");
  }

  @Test
  void testCreateTokenWithPermissions() {

    when(this.accessControl.isImpersonationTokensManageable()).thenReturn(true);
    when(this.tokenService.generateToken()).thenReturn("generated-token");
    when(this.tokenService.digestToken(anyString())).thenReturn("digested-token");

    Permission permission1 = mock(Permission.class);
    Permission permission2 = mock(Permission.class);
    List<Permission> permissions = List.of(permission1, permission2);
    AccessToken createdToken =
        AccessToken.builder()
            .id("1")
            .name("Test Token")
            .permissions(permissions)
            .createdAt(this.fixedClock.instant())
            .tokenType(TokenType.SERVICE)
            .build();
    when(this.accessTokenRepository.create(any(), anyString())).thenReturn(createdToken);

    this.useCase.createServiceToken(new CreateServiceTokenRequest("Test Token", permissions, null));

    verify(this.accessTokenRepository).create(any(), anyString());
  }

  @Test
  void testCreateTokenWithExpirationDate() {

    when(this.accessControl.isImpersonationTokensManageable()).thenReturn(true);
    when(this.tokenService.generateToken()).thenReturn("generated-token");
    when(this.tokenService.digestToken(anyString())).thenReturn("digested-token");

    Instant expiresAt = Instant.parse("2025-12-31T23:59:59Z");
    AccessToken createdToken =
        AccessToken.builder()
            .id("1")
            .name("Test Token")
            .createdAt(this.fixedClock.instant())
            .expiresAt(expiresAt)
            .tokenType(TokenType.SERVICE)
            .build();
    when(this.accessTokenRepository.create(any(), anyString())).thenReturn(createdToken);

    this.useCase.createServiceToken(
        new CreateServiceTokenRequest("Test Token", List.of(), expiresAt));

    verify(this.accessTokenRepository).create(any(), anyString());
  }
}

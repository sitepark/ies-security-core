package com.sitepark.ies.security.core.usecase.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.value.TokenType;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.Authentication;
import com.sitepark.ies.sharedkernel.security.User;
import com.sitepark.ies.sharedkernel.security.UserAuthentication;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class GetPrivateTokensUseCaseTest {

  private Authentication authentication;
  private AccessTokenRepository accessTokenRepository;
  private AccessControl accessControl;

  private GetPrivateTokensUseCase useCase;

  @BeforeEach
  void setUp() {
    this.authentication = mock(Authentication.class);
    this.accessTokenRepository = mock();
    this.accessControl = mock();

    this.useCase =
        new GetPrivateTokensUseCase(
            () -> this.authentication, this.accessTokenRepository, this.accessControl);
  }

  @Test
  void testAccessDeniedWhenNotUserAuthentication() {

    assertThrows(
        AccessDeniedException.class,
        () -> {
          this.useCase.getPrivateTokens();
        },
        "Should throw AccessDeniedException when authentication is not UserAuthentication");
  }

  @Test
  void testAccessDeniedWhenNotAllowed() {

    UserAuthentication userAuthentication = mock(UserAuthentication.class);
    User user = mock(User.class);
    when(user.id()).thenReturn("123");
    when(userAuthentication.user()).thenReturn(user);
    when(this.accessControl.isGetPrivateTokensAllowed("123")).thenReturn(false);

    GetPrivateTokensUseCase useCase =
        new GetPrivateTokensUseCase(
            () -> userAuthentication, this.accessTokenRepository, this.accessControl);

    assertThrows(
        AccessDeniedException.class,
        () -> {
          useCase.getPrivateTokens();
        },
        "Should throw AccessDeniedException when user is not allowed to get private tokens");
  }

  @Test
  void testVerifyAccessControlCalled() {

    UserAuthentication userAuthentication = mock(UserAuthentication.class);
    User user = mock(User.class);
    when(user.id()).thenReturn("123");
    when(userAuthentication.user()).thenReturn(user);
    when(this.accessControl.isGetPrivateTokensAllowed("123")).thenReturn(true);
    when(this.accessTokenRepository.getPrivateTokens("123")).thenReturn(List.of());

    GetPrivateTokensUseCase useCase =
        new GetPrivateTokensUseCase(
            () -> userAuthentication, this.accessTokenRepository, this.accessControl);

    useCase.getPrivateTokens();

    verify(this.accessControl).isGetPrivateTokensAllowed("123");
  }

  @Test
  void testVerifyRepositoryCalled() {

    UserAuthentication userAuthentication = mock(UserAuthentication.class);
    User user = mock(User.class);
    when(user.id()).thenReturn("123");
    when(userAuthentication.user()).thenReturn(user);
    when(this.accessControl.isGetPrivateTokensAllowed("123")).thenReturn(true);
    when(this.accessTokenRepository.getPrivateTokens("123")).thenReturn(List.of());

    GetPrivateTokensUseCase useCase =
        new GetPrivateTokensUseCase(
            () -> userAuthentication, this.accessTokenRepository, this.accessControl);

    useCase.getPrivateTokens();

    verify(this.accessTokenRepository).getPrivateTokens("123");
  }

  @Test
  void testReturnsCorrectTokenList() {

    UserAuthentication userAuthentication = mock(UserAuthentication.class);
    User user = mock(User.class);
    when(user.id()).thenReturn("123");
    when(userAuthentication.user()).thenReturn(user);
    when(this.accessControl.isGetPrivateTokensAllowed("123")).thenReturn(true);

    AccessToken token1 =
        AccessToken.builder()
            .id("1")
            .userId("123")
            .name("Token 1")
            .createdAt(Instant.parse("2025-01-01T10:00:00Z"))
            .tokenType(TokenType.PRIVATE)
            .build();

    AccessToken token2 =
        AccessToken.builder()
            .id("2")
            .userId("123")
            .name("Token 2")
            .createdAt(Instant.parse("2025-01-02T10:00:00Z"))
            .tokenType(TokenType.PRIVATE)
            .build();

    List<AccessToken> expectedTokens = List.of(token1, token2);
    when(this.accessTokenRepository.getPrivateTokens("123")).thenReturn(expectedTokens);

    GetPrivateTokensUseCase useCase =
        new GetPrivateTokensUseCase(
            () -> userAuthentication, this.accessTokenRepository, this.accessControl);

    List<AccessToken> result = useCase.getPrivateTokens();

    assertEquals(
        expectedTokens, result, "Should return the list of private tokens from the repository");
  }

  @Test
  void testReturnsEmptyListWhenNoTokens() {

    UserAuthentication userAuthentication = mock(UserAuthentication.class);
    User user = mock(User.class);
    when(user.id()).thenReturn("123");
    when(userAuthentication.user()).thenReturn(user);
    when(this.accessControl.isGetPrivateTokensAllowed("123")).thenReturn(true);
    when(this.accessTokenRepository.getPrivateTokens("123")).thenReturn(List.of());

    GetPrivateTokensUseCase useCase =
        new GetPrivateTokensUseCase(
            () -> userAuthentication, this.accessTokenRepository, this.accessControl);

    List<AccessToken> result = useCase.getPrivateTokens();

    assertEquals(List.of(), result, "Should return empty list when no private tokens exist");
  }
}

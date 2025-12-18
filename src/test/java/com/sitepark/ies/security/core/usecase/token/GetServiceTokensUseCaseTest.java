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
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class GetServiceTokensUseCaseTest {

  private AccessTokenRepository accessTokenRepository;
  private AccessControl accessControl;

  private GetServiceTokensUseCase useCase;

  @BeforeEach
  void setUp() {
    this.accessTokenRepository = mock();
    this.accessControl = mock();

    this.useCase = new GetServiceTokensUseCase(this.accessTokenRepository, this.accessControl);
  }

  @Test
  void testAccessDenied() {

    when(this.accessControl.isGetServiceTokensAllowed()).thenReturn(false);

    assertThrows(
        AccessDeniedException.class,
        () -> {
          this.useCase.getServiceTokens();
        },
        "Should throw AccessDeniedException when user is not allowed to get service tokens");
  }

  @Test
  void testVerifyAccessControlCalled() {

    when(this.accessControl.isGetServiceTokensAllowed()).thenReturn(true);
    when(this.accessTokenRepository.getServiceTokens()).thenReturn(List.of());

    this.useCase.getServiceTokens();

    verify(this.accessControl).isGetServiceTokensAllowed();
  }

  @Test
  void testVerifyRepositoryCalled() {

    when(this.accessControl.isGetServiceTokensAllowed()).thenReturn(true);
    when(this.accessTokenRepository.getServiceTokens()).thenReturn(List.of());

    this.useCase.getServiceTokens();

    verify(this.accessTokenRepository).getServiceTokens();
  }

  @Test
  void testReturnsCorrectTokenList() {

    when(this.accessControl.isGetServiceTokensAllowed()).thenReturn(true);

    AccessToken token1 =
        AccessToken.builder()
            .id("1")
            .name("Service Token 1")
            .createdAt(Instant.parse("2025-01-01T10:00:00Z"))
            .tokenType(TokenType.SERVICE)
            .build();

    AccessToken token2 =
        AccessToken.builder()
            .id("2")
            .name("Service Token 2")
            .createdAt(Instant.parse("2025-01-02T10:00:00Z"))
            .tokenType(TokenType.SERVICE)
            .build();

    List<AccessToken> expectedTokens = List.of(token1, token2);
    when(this.accessTokenRepository.getServiceTokens()).thenReturn(expectedTokens);

    List<AccessToken> result = this.useCase.getServiceTokens();

    assertEquals(
        expectedTokens, result, "Should return the list of service tokens from the repository");
  }

  @Test
  void testReturnsEmptyListWhenNoTokens() {

    when(this.accessControl.isGetServiceTokensAllowed()).thenReturn(true);
    when(this.accessTokenRepository.getServiceTokens()).thenReturn(List.of());

    List<AccessToken> result = this.useCase.getServiceTokens();

    assertEquals(List.of(), result, "Should return empty list when no service tokens exist");
  }
}

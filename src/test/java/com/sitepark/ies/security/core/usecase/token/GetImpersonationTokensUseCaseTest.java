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

class GetImpersonationTokensUseCaseTest {

  private AccessTokenRepository accessTokenRepository;
  private AccessControl accessControl;

  private GetImpersonationTokensUseCase useCase;

  @BeforeEach
  void setUp() {
    this.accessTokenRepository = mock();
    this.accessControl = mock();

    this.useCase =
        new GetImpersonationTokensUseCase(this.accessTokenRepository, this.accessControl);
  }

  @Test
  void testAccessDenied() {

    when(this.accessControl.isGetImpersonationTokensAllowed()).thenReturn(false);

    assertThrows(
        AccessDeniedException.class,
        () -> {
          this.useCase.getImpersonationTokens();
        },
        "Should throw AccessDeniedException when user is not allowed to get impersonation tokens");
  }

  @Test
  void testVerifyAccessControlCalled() {

    when(this.accessControl.isGetImpersonationTokensAllowed()).thenReturn(true);
    when(this.accessTokenRepository.getImpersonationTokens()).thenReturn(List.of());

    this.useCase.getImpersonationTokens();

    verify(this.accessControl).isGetImpersonationTokensAllowed();
  }

  @Test
  void testVerifyRepositoryCalled() {

    when(this.accessControl.isGetImpersonationTokensAllowed()).thenReturn(true);
    when(this.accessTokenRepository.getImpersonationTokens()).thenReturn(List.of());

    this.useCase.getImpersonationTokens();

    verify(this.accessTokenRepository).getImpersonationTokens();
  }

  @Test
  void testReturnsCorrectTokenList() {

    when(this.accessControl.isGetImpersonationTokensAllowed()).thenReturn(true);

    AccessToken token1 =
        AccessToken.builder()
            .id("1")
            .userId("user123")
            .name("Impersonation Token 1")
            .createdAt(Instant.parse("2025-01-01T10:00:00Z"))
            .tokenType(TokenType.IMPERSONATION)
            .build();

    AccessToken token2 =
        AccessToken.builder()
            .id("2")
            .userId("user456")
            .name("Impersonation Token 2")
            .createdAt(Instant.parse("2025-01-02T10:00:00Z"))
            .tokenType(TokenType.IMPERSONATION)
            .build();

    List<AccessToken> expectedTokens = List.of(token1, token2);
    when(this.accessTokenRepository.getImpersonationTokens()).thenReturn(expectedTokens);

    List<AccessToken> result = this.useCase.getImpersonationTokens();

    assertEquals(
        expectedTokens,
        result,
        "Should return the list of impersonation tokens from the repository");
  }

  @Test
  void testReturnsEmptyListWhenNoTokens() {

    when(this.accessControl.isGetImpersonationTokensAllowed()).thenReturn(true);
    when(this.accessTokenRepository.getImpersonationTokens()).thenReturn(List.of());

    List<AccessToken> result = this.useCase.getImpersonationTokens();

    assertEquals(List.of(), result, "Should return empty list when no impersonation tokens exist");
  }
}

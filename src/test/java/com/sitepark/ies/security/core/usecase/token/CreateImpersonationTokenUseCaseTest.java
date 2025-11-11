package com.sitepark.ies.security.core.usecase.token;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.exception.InvalidAccessTokenException;
import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.security.core.port.TokenService;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.User;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CreateImpersonationTokenUseCaseTest {

  private AccessTokenRepository accessTokenRepository;
  private AccessControl accessControl;
  private UserService userService;
  private final Clock fixedClock =
      Clock.fixed(Instant.parse("2025-06-30T10:00:00Z"), ZoneId.of("UTC"));

  private CreateImpersonationTokenUserCase useCase;

  @BeforeEach
  void setUp() {
    this.accessTokenRepository = mock();
    this.accessControl = mock();
    this.userService = mock();
    TokenService tokenService = mock();

    this.useCase =
        new CreateImpersonationTokenUserCase(
            this.accessTokenRepository,
            this.accessControl,
            tokenService,
            this.userService,
            this.fixedClock);
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testAccessDenied() {

    when(this.accessControl.isImpersonationTokensManageable()).thenReturn(false);
    assertThrows(
        AccessDeniedException.class,
        () -> {
          useCase.createImpersonationToken(
              new CreateImpersonationTokenRequest("123", "Test Token", null));
        });

    verify(accessControl).isImpersonationTokensManageable();
  }

  @Test
  void testUserNotFound() {

    when(this.accessControl.isImpersonationTokensManageable()).thenReturn(true);
    when(this.userService.findById(anyString())).thenReturn(Optional.empty());

    assertThrows(
        InvalidAccessTokenException.class,
        () -> {
          this.useCase.createImpersonationToken(
              new CreateImpersonationTokenRequest("123", "Test Token", null));
        });
  }

  @Test
  void testCreate() {

    when(this.accessControl.isImpersonationTokensManageable()).thenReturn(true);
    User user = mock(User.class);
    when(this.userService.findById(anyString())).thenReturn(Optional.of(user));

    this.useCase.createImpersonationToken(
        new CreateImpersonationTokenRequest("123", "Test Token", null));

    verify(this.accessTokenRepository).create(any(), any());
  }
}

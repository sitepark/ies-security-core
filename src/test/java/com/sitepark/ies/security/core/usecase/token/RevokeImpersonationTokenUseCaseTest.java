package com.sitepark.ies.security.core.usecase.token;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import org.junit.jupiter.api.Test;

class RevokeImpersonationTokenUseCaseTest {

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testAccessDenied() {

    AccessTokenRepository accessTokenRepository = mock();
    AccessControl accessControl = mock(AccessControl.class);
    when(accessControl.isImpersonationTokensManageable()).thenReturn(false);

    var revokeImpersonationToken =
        new RevokeImpersonationTokenUseCase(accessTokenRepository, accessControl);

    assertThrows(
        AccessDeniedException.class,
        () -> {
          revokeImpersonationToken.revokeImpersonationToken("2");
        });

    verify(accessControl).isImpersonationTokensManageable();
  }

  @Test
  void testRevoke() {

    AccessTokenRepository accessTokenRepository = mock();
    AccessControl accessControl = mock(AccessControl.class);
    when(accessControl.isImpersonationTokensManageable()).thenReturn(true);

    var revokeImpersonationToken =
        new RevokeImpersonationTokenUseCase(accessTokenRepository, accessControl);

    revokeImpersonationToken.revokeImpersonationToken("2");

    verify(accessTokenRepository).revoke("2");
  }
}

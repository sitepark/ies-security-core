package com.sitepark.ies.security.core.usecase;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import org.junit.jupiter.api.Test;

class RevokeImpersonationTokenTest {

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testAccessDenied() {

    AccessTokenRepository accessTokenRepository = mock();
    AccessControl accessControl = mock(AccessControl.class);
    when(accessControl.isImpersonationTokensManageable()).thenReturn(false);

    var revokeImpersonationToken =
        new RevokeImpersonationToken(accessTokenRepository, accessControl);

    assertThrows(
        AccessDeniedException.class,
        () -> {
          revokeImpersonationToken.revokeImpersonationToken("1", "2");
        });

    verify(accessControl).isImpersonationTokensManageable();
  }

  @Test
  void testRevoke() {

    AccessTokenRepository accessTokenRepository = mock();
    AccessControl accessControl = mock(AccessControl.class);
    when(accessControl.isImpersonationTokensManageable()).thenReturn(true);

    var revokeImpersonationToken =
        new RevokeImpersonationToken(accessTokenRepository, accessControl);

    revokeImpersonationToken.revokeImpersonationToken("1", "2");

    verify(accessTokenRepository).revoke("1", "2");
  }
}

package com.sitepark.ies.security.core.usecase.policy;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.value.AuthenticationPolicy;
import com.sitepark.ies.security.core.domain.value.AuthenticationPolicyLevel;
import com.sitepark.ies.security.core.port.AuthenticationPolicyRepository;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SetAuthenticationPolicyUseCaseTest {

  private AccessControl accessControl;
  private AuthenticationPolicyRepository repository;
  private SetAuthenticationPolicyUseCase useCase;

  @BeforeEach
  void setUp() {
    this.accessControl = mock();
    this.repository = mock();
    this.useCase = new SetAuthenticationPolicyUseCase(this.accessControl, this.repository);
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testAccessDenied() {
    assertThrows(
        AccessDeniedException.class,
        () -> this.useCase.setAuthenticationPolicy("7", AuthenticationPolicy.NONE),
        "setting a policy must need full access");
    verify(this.repository, never()).set(any(), any());
  }

  @Test
  void testSet() {
    when(this.accessControl.isSetAuthenticationPolicyAllowed()).thenReturn(true);
    AuthenticationPolicy policy =
        new AuthenticationPolicy(
            AuthenticationPolicyLevel.PASSKEY, Instant.parse("2026-12-01T00:00:00Z"));
    this.useCase.setAuthenticationPolicy("7", policy);
    verify(this.repository).set("7", policy);
  }

  @Test
  void testNoneRemoves() {
    when(this.accessControl.isSetAuthenticationPolicyAllowed()).thenReturn(true);
    this.useCase.setAuthenticationPolicy("7", AuthenticationPolicy.NONE);
    verify(this.repository).remove("7");
  }
}

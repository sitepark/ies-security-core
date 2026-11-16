package com.sitepark.ies.security.core.usecase.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.service.AuthenticationPolicyService;
import com.sitepark.ies.security.core.domain.value.AuthenticationPolicy;
import com.sitepark.ies.security.core.domain.value.AuthenticationPolicyLevel;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class GetAuthenticationPolicyUseCaseTest {

  private AccessControl accessControl;
  private AuthenticationPolicyService policyService;
  private GetAuthenticationPolicyUseCase useCase;

  @BeforeEach
  void setUp() {
    this.accessControl = mock();
    this.policyService = mock();
    this.useCase = new GetAuthenticationPolicyUseCase(this.accessControl, this.policyService);
  }

  @Test
  void testAccessDenied() {
    assertThrows(
        AccessDeniedException.class,
        () -> this.useCase.getAuthenticationPolicy("7"),
        "reading another user's policy must need access");
  }

  @Test
  void testGet() {
    AuthenticationPolicy policy =
        new AuthenticationPolicy(AuthenticationPolicyLevel.SECOND_FACTOR, null);
    when(this.accessControl.isGetAuthenticationPolicyAllowed("7")).thenReturn(true);
    when(this.policyService.getPolicy("7")).thenReturn(policy);
    assertEquals(
        policy, this.useCase.getAuthenticationPolicy("7"), "the stored policy must be returned");
  }
}

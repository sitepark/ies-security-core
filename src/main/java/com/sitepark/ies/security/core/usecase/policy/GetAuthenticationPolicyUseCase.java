package com.sitepark.ies.security.core.usecase.policy;

import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.service.AuthenticationPolicyService;
import com.sitepark.ies.security.core.domain.value.AuthenticationPolicy;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import jakarta.inject.Inject;

/** Returns the authentication policy of a user; users without a policy get {@code NONE}. */
public class GetAuthenticationPolicyUseCase {

  private final AccessControl accessControl;

  private final AuthenticationPolicyService policyService;

  @Inject
  protected GetAuthenticationPolicyUseCase(
      AccessControl accessControl, AuthenticationPolicyService policyService) {
    this.accessControl = accessControl;
    this.policyService = policyService;
  }

  public AuthenticationPolicy getAuthenticationPolicy(String userId) {
    if (!this.accessControl.isGetAuthenticationPolicyAllowed(userId)) {
      throw new AccessDeniedException(
          "Reading the authentication policy is not allowed for user: " + userId);
    }
    return this.policyService.getPolicy(userId);
  }
}

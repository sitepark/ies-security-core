package com.sitepark.ies.security.core.usecase.policy;

import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.service.AuthenticationPolicyService;
import com.sitepark.ies.security.core.domain.value.AuthenticationPolicy;
import com.sitepark.ies.security.core.domain.value.AuthenticationPolicyLevel;
import com.sitepark.ies.security.core.port.AuthenticationPolicyRepository;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import jakarta.inject.Inject;

/**
 * Sets the authentication policy of a user. Setting a new deadline is also the way back for a user
 * who missed the deadline or lost the passkeys.
 */
public class SetAuthenticationPolicyUseCase {

  private final AccessControl accessControl;

  private final AuthenticationPolicyRepository repository;

  private final AuthenticationPolicyService policyService;

  @Inject
  protected SetAuthenticationPolicyUseCase(
      AccessControl accessControl,
      AuthenticationPolicyRepository repository,
      AuthenticationPolicyService policyService) {
    this.accessControl = accessControl;
    this.repository = repository;
    this.policyService = policyService;
  }

  public void setAuthenticationPolicy(String userId, AuthenticationPolicy policy) {
    if (!this.accessControl.isSetAuthenticationPolicyAllowed()) {
      throw new AccessDeniedException(
          "Setting the authentication policy is not allowed for user: " + userId);
    }
    // a policy that needs a switched-off factor would lock the user out
    this.policyService.requirePolicyAllowed(policy);
    if (policy.level() == AuthenticationPolicyLevel.NONE) {
      this.repository.remove(userId);
    } else {
      this.repository.set(userId, policy);
    }
  }
}

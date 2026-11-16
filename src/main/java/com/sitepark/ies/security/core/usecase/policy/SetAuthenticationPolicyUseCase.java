package com.sitepark.ies.security.core.usecase.policy;

import com.sitepark.ies.security.core.domain.service.AccessControl;
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

  @Inject
  protected SetAuthenticationPolicyUseCase(
      AccessControl accessControl, AuthenticationPolicyRepository repository) {
    this.accessControl = accessControl;
    this.repository = repository;
  }

  public void setAuthenticationPolicy(String userId, AuthenticationPolicy policy) {
    if (!this.accessControl.isSetAuthenticationPolicyAllowed()) {
      throw new AccessDeniedException(
          "Setting the authentication policy is not allowed for user: " + userId);
    }
    if (policy.level() == AuthenticationPolicyLevel.NONE) {
      this.repository.remove(userId);
    } else {
      this.repository.set(userId, policy);
    }
  }
}

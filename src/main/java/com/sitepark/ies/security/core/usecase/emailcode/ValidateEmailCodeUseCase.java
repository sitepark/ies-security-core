package com.sitepark.ies.security.core.usecase.emailcode;

import com.sitepark.ies.security.core.domain.exception.AuthenticationProcessNotFoundException;
import com.sitepark.ies.security.core.domain.exception.EmailCodeNotRequiredException;
import com.sitepark.ies.security.core.domain.service.AuthenticationPolicyService;
import com.sitepark.ies.security.core.domain.service.EmailCodeService;
import com.sitepark.ies.security.core.domain.value.AuthenticationFailureReason;
import com.sitepark.ies.security.core.domain.value.AuthenticationRequirement;
import com.sitepark.ies.security.core.domain.value.AuthenticationResult;
import com.sitepark.ies.security.core.domain.value.PartialAuthenticationState;
import com.sitepark.ies.security.core.domain.value.PolicyDecision;
import com.sitepark.ies.security.core.port.TotpAuthenticationProcessStore;
import jakarta.inject.Inject;
import java.util.List;

/** Completes a login that waits for the e-mail code. */
public class ValidateEmailCodeUseCase {

  private final TotpAuthenticationProcessStore authenticationProcessStore;
  private final EmailCodeService emailCodeService;
  private final AuthenticationPolicyService policyService;

  @Inject
  protected ValidateEmailCodeUseCase(
      TotpAuthenticationProcessStore authenticationProcessStore,
      EmailCodeService emailCodeService,
      AuthenticationPolicyService policyService) {
    this.authenticationProcessStore = authenticationProcessStore;
    this.emailCodeService = emailCodeService;
    this.policyService = policyService;
  }

  public AuthenticationResult validateEmailCode(String authProcessId, int code) {

    PartialAuthenticationState authState =
        this.authenticationProcessStore
            .retrieve(authProcessId)
            .orElseThrow(AuthenticationProcessNotFoundException::new);

    if (!authState.requirements().contains(AuthenticationRequirement.EMAIL_CODE_REQUIRED)
        || authState.emailCodeChallengeId() == null) {
      throw new EmailCodeNotRequiredException();
    }

    if (!this.emailCodeService.verify(authState.user(), authState.emailCodeChallengeId(), code)) {
      return AuthenticationResult.failure();
    }

    List<AuthenticationRequirement> remainingRequirements =
        authState.requirements().stream()
            .filter(requirement -> requirement != AuthenticationRequirement.EMAIL_CODE_REQUIRED)
            .toList();

    if (!remainingRequirements.isEmpty()) {
      return AuthenticationResult.partial(authProcessId, remainingRequirements);
    }

    this.authenticationProcessStore.remove(authProcessId);
    // decided again because the deadline may have expired since the password step
    PolicyDecision decision = this.policyService.decidePasswordLogin(authState.user(), true);
    if (decision instanceof PolicyDecision.Denied(AuthenticationFailureReason reason)) {
      return AuthenticationResult.failure(reason);
    }
    return AuthenticationResult.success(authState.user(), authState.purpose())
        .withPolicyNotice(((PolicyDecision.Allowed) decision).notice());
  }
}

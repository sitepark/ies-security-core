package com.sitepark.ies.security.core.usecase.emailcode;

import com.sitepark.ies.security.core.domain.exception.NoEmailAddressException;
import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.service.AuthenticationPolicyService;
import com.sitepark.ies.security.core.domain.value.AuthFactorType;
import com.sitepark.ies.security.core.domain.value.EmailCodeSetupPayload;
import com.sitepark.ies.security.core.port.EmailCodeSender;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.CodeVerificationChallenge;
import com.sitepark.ies.sharedkernel.security.CodeVerificationService;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;

/**
 * Sends a code to the e-mail address of the account; {@link ConfirmEmailCodeSetupUseCase} activates
 * the e-mail code as second factor once the code is entered. The address is confirmed this way, and
 * later codes go to this confirmed address even if the account address changes.
 */
public class StartEmailCodeSetupUseCase {

  private final UserService userService;
  private final AccessControl accessControl;
  private final AuthenticationPolicyService policyService;
  private final CodeVerificationService codeVerificationService;
  private final EmailCodeSender emailCodeSender;

  @Inject
  protected StartEmailCodeSetupUseCase(
      UserService userService,
      AccessControl accessControl,
      AuthenticationPolicyService policyService,
      CodeVerificationService codeVerificationService,
      EmailCodeSender emailCodeSender) {
    this.userService = userService;
    this.accessControl = accessControl;
    this.policyService = policyService;
    this.codeVerificationService = codeVerificationService;
    this.emailCodeSender = emailCodeSender;
  }

  /** Returns the id of the challenge to confirm. */
  public String startEmailCodeSetup(String userId) {
    this.policyService.requireFactorAllowed(AuthFactorType.EMAIL_CODE);
    if (!this.accessControl.isEmailCodeManageable(userId)) {
      throw new AccessDeniedException(
          "Setting up the e-mail code is not allowed for user: " + userId);
    }
    User user =
        this.userService
            .findById(userId)
            .orElseThrow(
                () ->
                    new AccessDeniedException(
                        "Setting up the e-mail code is not allowed for user: " + userId));
    String address = user.email();
    if (address == null || address.isBlank()) {
      throw new NoEmailAddressException(userId);
    }
    CodeVerificationChallenge challenge =
        this.codeVerificationService.startChallenge(new EmailCodeSetupPayload(userId, address));
    if (challenge.sendCode()) {
      this.emailCodeSender.send(user, address, challenge);
    }
    return challenge.challengeId();
  }
}

package com.sitepark.ies.security.core.usecase.password;

import com.sitepark.ies.security.core.domain.exception.FinishPasswordRecoveryException;
import com.sitepark.ies.security.core.domain.service.AuthenticationPolicyService;
import com.sitepark.ies.security.core.domain.service.SetPasswordService;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.email.Email;
import com.sitepark.ies.sharedkernel.email.EmailAddress;
import com.sitepark.ies.sharedkernel.email.EmailMessage;
import com.sitepark.ies.sharedkernel.email.EmailMessageTypeIdentifier;
import com.sitepark.ies.sharedkernel.email.EmailSendException;
import com.sitepark.ies.sharedkernel.email.EmailService;
import com.sitepark.ies.sharedkernel.email.ExternalEmailParameters;
import com.sitepark.ies.sharedkernel.email.TemplateEmailMessage;
import com.sitepark.ies.sharedkernel.security.CodeVerificationChallenge;
import com.sitepark.ies.sharedkernel.security.CodeVerificationFailedException;
import com.sitepark.ies.sharedkernel.security.CodeVerificationService;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class FinishPasswordRecoveryUseCase {

  public static final EmailMessageTypeIdentifier PASSWORD_RECOVERY_CONFIRMATION =
      new EmailMessageTypeIdentifier("notification", "password-recovery-confirmation");

  private final CodeVerificationService codeVerificationService;

  private final UserService userService;

  private final SetPasswordService setPasswordService;

  private final EmailService emailService;

  private final AuthenticationPolicyService policyService;

  @Inject
  FinishPasswordRecoveryUseCase(
      CodeVerificationService codeVerificationService,
      UserService userService,
      SetPasswordService setPasswordService,
      EmailService emailService,
      AuthenticationPolicyService policyService) {
    this.codeVerificationService = codeVerificationService;
    this.userService = userService;
    this.setPasswordService = setPasswordService;
    this.emailService = emailService;
    this.policyService = policyService;
  }

  public void finishPasswordRecovery(FinishPasswordRecoveryRequest request) {
    CodeVerificationChallenge challenge =
        this.codeVerificationService.finishChallenge(request.challengeId(), request.code());

    if (!(challenge.payload() instanceof PasswordRecoverPayload(String username))) {
      throw new CodeVerificationFailedException("Payload is not PasswordRecoverPayload");
    }

    User user =
        this.userService
            .findByUsername(username)
            .orElseThrow(() -> new CodeVerificationFailedException("User not found"));

    // a code sent before the passkey deadline must not bring the password back afterwards
    if (!this.policyService.isPasswordRecoveryAllowed(user)) {
      throw new CodeVerificationFailedException("Password recovery not allowed by policy");
    }

    this.setPasswordService.setPassword(user.id(), request.newPassword());

    this.sendEmail(request, user);
  }

  private void sendEmail(FinishPasswordRecoveryRequest request, User user) {

    EmailMessage message = this.createEmailMessage(request.emailParameters(), user);

    Email email =
        Email.builder()
            .from(request.emailParameters().from())
            .replyTo(configurer -> configurer.set(request.emailParameters().replyTo()))
            .to(
                configurer ->
                    configurer.set(
                        EmailAddress.builder()
                            .address(
                                Objects.requireNonNull(user.email(), "user has no email address"))
                            .name(user.toDisplayName())
                            .build()))
            .message(message)
            .build();
    try {
      this.emailService.send(email);
    } catch (EmailSendException e) {
      throw new FinishPasswordRecoveryException("Send email failed", e);
    }
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private TemplateEmailMessage createEmailMessage(ExternalEmailParameters parameters, User user) {
    Map<String, Object> data = new HashMap<>();
    data.put("user", user);

    return TemplateEmailMessage.builder()
        .messageType(PASSWORD_RECOVERY_CONFIRMATION)
        .theme(parameters.theme())
        .lang(parameters.lang())
        .data(configurer -> configurer.putAll(data))
        .build();
  }
}

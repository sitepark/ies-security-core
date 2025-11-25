package com.sitepark.ies.security.core.usecase.password;

import com.sitepark.ies.security.core.domain.exception.CodeVerificationFailedException;
import com.sitepark.ies.security.core.domain.exception.FinishPasswordRecoveryException;
import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.service.SetPasswordService;
import com.sitepark.ies.security.core.domain.value.CodeVerificationChallenge;
import com.sitepark.ies.security.core.port.CodeVerificationService;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.email.Email;
import com.sitepark.ies.sharedkernel.email.EmailAddress;
import com.sitepark.ies.sharedkernel.email.EmailMessage;
import com.sitepark.ies.sharedkernel.email.EmailSendException;
import com.sitepark.ies.sharedkernel.email.EmailService;
import com.sitepark.ies.sharedkernel.email.SimpleEmailMessage;
import com.sitepark.ies.sharedkernel.email.TemplateEmailMessage;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;
import java.util.HashMap;
import java.util.Map;

public class FinishPasswordRecoveryUseCase {

  private final CodeVerificationService codeVerificationService;

  private final UserService userService;

  private final SetPasswordService setPasswordService;

  private final EmailService emailService;

  private final AccessControl accessControl;

  @Inject
  FinishPasswordRecoveryUseCase(
      CodeVerificationService codeVerificationService,
      UserService userService,
      SetPasswordService setPasswordService,
      EmailService emailService,
      AccessControl accessControl) {
    this.codeVerificationService = codeVerificationService;
    this.userService = userService;
    this.setPasswordService = setPasswordService;
    this.emailService = emailService;
    this.accessControl = accessControl;
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

    this.setPasswordService.setPassword(user.id(), request.newPassword());

    this.sendEmail(request, user);
  }

  private void sendEmail(FinishPasswordRecoveryRequest request, User user) {

    EmailMessage message = this.updateEmailMessage(request.message(), user);

    if (message instanceof SimpleEmailMessage
        && !this.accessControl.isAllowedToSendCustomEmails()) {
      throw new AccessDeniedException("Sending custom email messages is not allowed");
    }

    Email email =
        Email.builder()
            .from(request.from())
            .replyTo(configurer -> configurer.set(request.replyTo()))
            .to(
                configurer ->
                    configurer.set(
                        EmailAddress.builder()
                            .address(user.email())
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
  private EmailMessage updateEmailMessage(EmailMessage message, User user) {
    Map<String, Object> data = new HashMap<>();
    data.put("user", user);
    if (message instanceof SimpleEmailMessage(String subject, String html, String text)) {
      String resolvedSubject = this.emailService.resolveMessage(subject, data);
      String resolvedHtml = this.emailService.resolveMessage(html, data);
      String resolvedText = this.emailService.resolveMessage(text, data);
      return new SimpleEmailMessage(resolvedSubject, resolvedHtml, resolvedText);
    } else if (message instanceof TemplateEmailMessage template) {
      return template.toBuilder()
          .data(configurer -> configurer.putAll(template.data()).putAll(data))
          .build();
    } else {
      throw new IllegalArgumentException(
          "Unsupported email message type " + message.getClass().getName());
    }
  }
}

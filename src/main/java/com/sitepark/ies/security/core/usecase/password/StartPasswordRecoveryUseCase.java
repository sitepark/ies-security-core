package com.sitepark.ies.security.core.usecase.password;

import com.sitepark.ies.security.core.domain.exception.StartPasswordRecoveryException;
import com.sitepark.ies.security.core.domain.service.AccessControl;
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
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public final class StartPasswordRecoveryUseCase {

  private final CodeVerificationService codeVerificationService;

  private final UserService userService;

  private final EmailService emailService;

  private final AccessControl accessControl;

  @Inject
  StartPasswordRecoveryUseCase(
      UserService userService,
      CodeVerificationService codeVerificationService,
      EmailService emailService,
      AccessControl accessControl) {
    this.userService = userService;
    this.codeVerificationService = codeVerificationService;
    this.emailService = emailService;
    this.accessControl = accessControl;
  }

  public StartPasswordRecoveryResult startPasswordRecovery(StartPasswordRecoveryRequest request) {

    Optional<User> optUser = this.userService.findByUsername(request.username());

    if (optUser.isEmpty()) {
      return this.createFakeChallenge();
    }

    User user = optUser.get();
    if (user.email() == null) {
      return this.createFakeChallenge();
    }

    return this.startChallenge(user, request);
  }

  private StartPasswordRecoveryResult createFakeChallenge() {
    CodeVerificationChallenge challenge = this.codeVerificationService.createFakeChallenge();
    return new StartPasswordRecoveryResult(
        challenge.challengeId(), challenge.createdAt(), challenge.expiresAt());
  }

  private StartPasswordRecoveryResult startChallenge(
      User user, StartPasswordRecoveryRequest request) {

    PasswordRecoverPayload payload = new PasswordRecoverPayload(request.username());

    CodeVerificationChallenge challenge = this.codeVerificationService.startChallenge(payload);

    this.sendEmail(request, user, challenge);

    return new StartPasswordRecoveryResult(
        challenge.challengeId(), challenge.createdAt(), challenge.expiresAt());
  }

  private void sendEmail(
      StartPasswordRecoveryRequest request, User user, CodeVerificationChallenge challenge) {

    EmailMessage message = this.updateEmailMessage(request.message(), user, challenge);

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
      throw new StartPasswordRecoveryException("Send email failed", e);
    }
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private EmailMessage updateEmailMessage(
      EmailMessage message, User user, CodeVerificationChallenge challenge) {
    Map<String, Object> data = new HashMap<>();
    data.put("code", challenge.code());
    data.put("expiresAt", formatExpiresAt(challenge.expiresAt()));
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

  private String formatExpiresAt(Instant expiresAt) {
    return expiresAt
        .atZone(java.time.ZoneId.systemDefault())
        .toLocalTime()
        .format(DateTimeFormatter.ofPattern("HH:mm"));
  }
}

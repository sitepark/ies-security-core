package com.sitepark.ies.security.core.usecase.password;

import com.sitepark.ies.security.core.domain.exception.StartPasswordRecoveryException;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.email.Email;
import com.sitepark.ies.sharedkernel.email.EmailAddress;
import com.sitepark.ies.sharedkernel.email.EmailMessageTypeIdentifier;
import com.sitepark.ies.sharedkernel.email.EmailSendException;
import com.sitepark.ies.sharedkernel.email.EmailService;
import com.sitepark.ies.sharedkernel.email.ExternalEmailParameters;
import com.sitepark.ies.sharedkernel.email.TemplateEmailMessage;
import com.sitepark.ies.sharedkernel.security.CodeVerificationChallenge;
import com.sitepark.ies.sharedkernel.security.CodeVerificationService;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public final class StartPasswordRecoveryUseCase {

  public static final EmailMessageTypeIdentifier PASSWORD_RECOVERY_SEND_VERIFICATION_CODE =
      new EmailMessageTypeIdentifier("notification", "password-recovery-send-verification-code");

  private final CodeVerificationService codeVerificationService;

  private final UserService userService;

  private final EmailService emailService;

  @Inject
  StartPasswordRecoveryUseCase(
      UserService userService,
      CodeVerificationService codeVerificationService,
      EmailService emailService) {
    this.userService = userService;
    this.codeVerificationService = codeVerificationService;
    this.emailService = emailService;
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

    TemplateEmailMessage message =
        this.createEmailMessage(request.emailParameters(), user, challenge);

    Email email =
        Email.builder()
            .from(request.emailParameters().from())
            .replyTo(configurer -> configurer.set(request.emailParameters().replyTo()))
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
  private TemplateEmailMessage createEmailMessage(
      ExternalEmailParameters parameters, User user, CodeVerificationChallenge challenge) {
    Map<String, Object> data = new HashMap<>();
    data.put("code", challenge.code());
    data.put("expiresAt", formatExpiresAt(challenge.expiresAt()));
    data.put("user", user);

    return TemplateEmailMessage.builder()
        .messageType(PASSWORD_RECOVERY_SEND_VERIFICATION_CODE)
        .theme(parameters.theme())
        .lang(parameters.lang())
        .data(configurer -> configurer.putAll(data))
        .build();
  }

  private String formatExpiresAt(Instant expiresAt) {
    return expiresAt
        .atZone(java.time.ZoneId.systemDefault())
        .toLocalTime()
        .format(DateTimeFormatter.ofPattern("HH:mm"));
  }
}

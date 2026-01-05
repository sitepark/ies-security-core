package com.sitepark.ies.security.core.usecase.password;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.exception.FinishPasswordRecoveryException;
import com.sitepark.ies.security.core.domain.service.SetPasswordService;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.email.EmailAddress;
import com.sitepark.ies.sharedkernel.email.EmailMessageThemeIdentifier;
import com.sitepark.ies.sharedkernel.email.EmailSendException;
import com.sitepark.ies.sharedkernel.email.EmailService;
import com.sitepark.ies.sharedkernel.email.ExternalEmailParameters;
import com.sitepark.ies.sharedkernel.email.TemplateEmailMessage;
import com.sitepark.ies.sharedkernel.security.CodeVerificationChallenge;
import com.sitepark.ies.sharedkernel.security.CodeVerificationFailedException;
import com.sitepark.ies.sharedkernel.security.CodeVerificationService;
import com.sitepark.ies.sharedkernel.security.User;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class FinishPasswordRecoveryUseCaseTest {

  private static final EmailMessageThemeIdentifier THEME =
      EmailMessageThemeIdentifier.of("registration", "test");

  private static final String LANG = "en";

  public static final ExternalEmailParameters EMAIL_PARAMETERS =
      new ExternalEmailParameters(mock(EmailAddress.class), List.of(), THEME, LANG);

  private CodeVerificationService codeVerificationService;
  private UserService userService;
  private SetPasswordService setPasswordService;
  private EmailService emailService;

  private FinishPasswordRecoveryUseCase useCase;

  @BeforeEach
  void setUp() {
    this.codeVerificationService = mock();
    this.userService = mock();
    this.setPasswordService = mock();
    this.emailService = mock();

    this.useCase =
        new FinishPasswordRecoveryUseCase(
            this.codeVerificationService,
            this.userService,
            this.setPasswordService,
            this.emailService);
  }

  @Test
  void testInvalidPayloadTypeThrowsException() {

    CodeVerificationChallenge challenge =
        new CodeVerificationChallenge(
            "challenge-123",
            123456,
            null,
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"),
            0);
    when(this.codeVerificationService.finishChallenge("challenge-123", 123456))
        .thenReturn(challenge);

    FinishPasswordRecoveryRequest request =
        new FinishPasswordRecoveryRequest("challenge-123", 123456, "newPassword", EMAIL_PARAMETERS);

    assertThrows(
        CodeVerificationFailedException.class,
        () -> {
          this.useCase.finishPasswordRecovery(request);
        },
        "Should throw CodeVerificationFailedException when payload is not PasswordRecoverPayload");
  }

  @Test
  void testUserNotFoundThrowsException() {

    PasswordRecoverPayload payload = new PasswordRecoverPayload("unknown");
    CodeVerificationChallenge challenge =
        new CodeVerificationChallenge(
            "challenge-123",
            123456,
            payload,
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"),
            0);
    when(this.codeVerificationService.finishChallenge("challenge-123", 123456))
        .thenReturn(challenge);
    when(this.userService.findByUsername("unknown")).thenReturn(Optional.empty());

    FinishPasswordRecoveryRequest request =
        new FinishPasswordRecoveryRequest("challenge-123", 123456, "newPassword", EMAIL_PARAMETERS);

    assertThrows(
        CodeVerificationFailedException.class,
        () -> {
          this.useCase.finishPasswordRecovery(request);
        },
        "Should throw CodeVerificationFailedException when user is not found");
  }

  @Test
  void testSuccessfulPasswordRecovery() {

    User user = mock(User.class);
    when(user.id()).thenReturn("user123");
    when(user.email()).thenReturn("user@example.com");
    when(user.toDisplayName()).thenReturn("Test User");

    PasswordRecoverPayload payload = new PasswordRecoverPayload("validUser");
    CodeVerificationChallenge challenge =
        new CodeVerificationChallenge(
            "challenge-789",
            789012,
            payload,
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"),
            0);
    when(this.codeVerificationService.finishChallenge("challenge-789", 789012))
        .thenReturn(challenge);
    when(this.userService.findByUsername("validUser")).thenReturn(Optional.of(user));

    TemplateEmailMessage message = mock(TemplateEmailMessage.class);
    TemplateEmailMessage.Builder builder = mock(TemplateEmailMessage.Builder.class);
    when(message.toBuilder()).thenReturn(builder);
    when(message.data()).thenReturn(Map.of());
    when(builder.data(any())).thenReturn(builder);
    when(builder.build()).thenReturn(message);

    FinishPasswordRecoveryRequest request =
        new FinishPasswordRecoveryRequest(
            "challenge-789", 789012, "newSecurePassword", EMAIL_PARAMETERS);

    this.useCase.finishPasswordRecovery(request);

    verify(this.setPasswordService).setPassword("user123", "newSecurePassword");
  }

  @Test
  void testSuccessfulPasswordRecoverySendsEmail() throws EmailSendException {

    User user = mock(User.class);
    when(user.id()).thenReturn("user123");
    when(user.email()).thenReturn("user@example.com");
    when(user.toDisplayName()).thenReturn("Test User");

    PasswordRecoverPayload payload = new PasswordRecoverPayload("validUser");
    CodeVerificationChallenge challenge =
        new CodeVerificationChallenge(
            "challenge-789",
            789012,
            payload,
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"),
            0);
    when(this.codeVerificationService.finishChallenge("challenge-789", 789012))
        .thenReturn(challenge);
    when(this.userService.findByUsername("validUser")).thenReturn(Optional.of(user));

    TemplateEmailMessage message = mock(TemplateEmailMessage.class);
    TemplateEmailMessage.Builder builder = mock(TemplateEmailMessage.Builder.class);
    when(message.toBuilder()).thenReturn(builder);
    when(message.data()).thenReturn(Map.of());
    when(builder.data(any())).thenReturn(builder);
    when(builder.build()).thenReturn(message);

    FinishPasswordRecoveryRequest request =
        new FinishPasswordRecoveryRequest(
            "challenge-789", 789012, "newSecurePassword", EMAIL_PARAMETERS);

    this.useCase.finishPasswordRecovery(request);

    verify(this.emailService).send(any());
  }

  @Test
  void testEmailSendFailureThrowsException() throws EmailSendException {

    User user = mock(User.class);
    when(user.id()).thenReturn("user123");
    when(user.email()).thenReturn("user@example.com");
    when(user.toDisplayName()).thenReturn("Test User");

    PasswordRecoverPayload payload = new PasswordRecoverPayload("validUser");
    CodeVerificationChallenge challenge =
        new CodeVerificationChallenge(
            "challenge-789",
            789012,
            payload,
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"),
            0);
    when(this.codeVerificationService.finishChallenge("challenge-789", 789012))
        .thenReturn(challenge);
    when(this.userService.findByUsername("validUser")).thenReturn(Optional.of(user));

    TemplateEmailMessage message = mock(TemplateEmailMessage.class);
    TemplateEmailMessage.Builder builder = mock(TemplateEmailMessage.Builder.class);
    when(message.toBuilder()).thenReturn(builder);
    when(message.data()).thenReturn(Map.of());
    when(builder.data(any())).thenReturn(builder);
    when(builder.build()).thenReturn(message);

    doThrow(new EmailSendException("Failed to send")).when(this.emailService).send(any());

    FinishPasswordRecoveryRequest request =
        new FinishPasswordRecoveryRequest(
            "challenge-789", 789012, "newSecurePassword", EMAIL_PARAMETERS);

    assertThrows(
        FinishPasswordRecoveryException.class,
        () -> {
          this.useCase.finishPasswordRecovery(request);
        },
        "Should throw FinishPasswordRecoveryException when email send fails");
  }

  @Test
  void testVerifyCodeVerificationServiceCalled() {

    User user = mock(User.class);
    when(user.id()).thenReturn("user123");
    when(user.email()).thenReturn("user@example.com");
    when(user.toDisplayName()).thenReturn("Test User");

    PasswordRecoverPayload payload = new PasswordRecoverPayload("validUser");
    CodeVerificationChallenge challenge =
        new CodeVerificationChallenge(
            "challenge-789",
            789012,
            payload,
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"),
            0);
    when(this.codeVerificationService.finishChallenge("challenge-789", 789012))
        .thenReturn(challenge);
    when(this.userService.findByUsername("validUser")).thenReturn(Optional.of(user));

    TemplateEmailMessage message = mock(TemplateEmailMessage.class);
    TemplateEmailMessage.Builder builder = mock(TemplateEmailMessage.Builder.class);
    when(message.toBuilder()).thenReturn(builder);
    when(message.data()).thenReturn(Map.of());
    when(builder.data(any())).thenReturn(builder);
    when(builder.build()).thenReturn(message);

    FinishPasswordRecoveryRequest request =
        new FinishPasswordRecoveryRequest(
            "challenge-789", 789012, "newSecurePassword", EMAIL_PARAMETERS);

    this.useCase.finishPasswordRecovery(request);

    verify(this.codeVerificationService).finishChallenge("challenge-789", 789012);
  }

  @Test
  void testVerifyUserServiceCalled() {

    User user = mock(User.class);
    when(user.id()).thenReturn("user123");
    when(user.email()).thenReturn("user@example.com");
    when(user.toDisplayName()).thenReturn("Test User");

    PasswordRecoverPayload payload = new PasswordRecoverPayload("validUser");
    CodeVerificationChallenge challenge =
        new CodeVerificationChallenge(
            "challenge-789",
            789012,
            payload,
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"),
            0);
    when(this.codeVerificationService.finishChallenge(anyString(), anyInt())).thenReturn(challenge);
    when(this.userService.findByUsername("validUser")).thenReturn(Optional.of(user));

    TemplateEmailMessage message = mock(TemplateEmailMessage.class);
    TemplateEmailMessage.Builder builder = mock(TemplateEmailMessage.Builder.class);
    when(message.toBuilder()).thenReturn(builder);
    when(message.data()).thenReturn(Map.of());
    when(builder.data(any())).thenReturn(builder);
    when(builder.build()).thenReturn(message);

    FinishPasswordRecoveryRequest request =
        new FinishPasswordRecoveryRequest(
            "challenge-789", 789012, "newSecurePassword", EMAIL_PARAMETERS);

    this.useCase.finishPasswordRecovery(request);

    verify(this.userService).findByUsername("validUser");
  }
}

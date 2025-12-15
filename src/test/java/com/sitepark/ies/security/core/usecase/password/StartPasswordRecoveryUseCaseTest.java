package com.sitepark.ies.security.core.usecase.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.exception.StartPasswordRecoveryException;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.email.EmailAddress;
import com.sitepark.ies.sharedkernel.email.EmailMessageThemeIdentifier;
import com.sitepark.ies.sharedkernel.email.EmailSendException;
import com.sitepark.ies.sharedkernel.email.EmailService;
import com.sitepark.ies.sharedkernel.email.ExternalEmailParameters;
import com.sitepark.ies.sharedkernel.email.TemplateEmailMessage;
import com.sitepark.ies.sharedkernel.security.CodeVerificationChallenge;
import com.sitepark.ies.sharedkernel.security.CodeVerificationService;
import com.sitepark.ies.sharedkernel.security.User;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class StartPasswordRecoveryUseCaseTest {

  private static final EmailMessageThemeIdentifier THEME =
      EmailMessageThemeIdentifier.of("registration", "test");

  private static final String LANG = "en";

  public static final ExternalEmailParameters EMAIL_PARAMETERS =
      new ExternalEmailParameters(mock(EmailAddress.class), List.of(), THEME, LANG);

  private CodeVerificationService codeVerificationService;
  private UserService userService;
  private EmailService emailService;

  private StartPasswordRecoveryUseCase useCase;

  @BeforeEach
  void setUp() {
    this.codeVerificationService = mock();
    this.userService = mock();
    this.emailService = mock();

    this.useCase =
        new StartPasswordRecoveryUseCase(
            this.userService, this.codeVerificationService, this.emailService);
  }

  @Test
  void testUserNotFoundReturnsFakeChallenge() {

    when(this.userService.findByUsername("unknown")).thenReturn(Optional.empty());

    CodeVerificationChallenge fakeChallenge =
        new CodeVerificationChallenge(
            "fake-123",
            123456,
            null,
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"),
            0);
    when(this.codeVerificationService.createFakeChallenge()).thenReturn(fakeChallenge);

    StartPasswordRecoveryRequest request =
        new StartPasswordRecoveryRequest("unknown", EMAIL_PARAMETERS);

    StartPasswordRecoveryResult result = this.useCase.startPasswordRecovery(request);

    assertEquals(
        "fake-123", result.challengeId(), "Should return fake challenge ID when user not found");
  }

  @Test
  void testUserWithoutEmailReturnsFakeChallenge() {

    User user = mock(User.class);
    when(user.email()).thenReturn(null);
    when(this.userService.findByUsername("userWithoutEmail")).thenReturn(Optional.of(user));

    CodeVerificationChallenge fakeChallenge =
        new CodeVerificationChallenge(
            "fake-456",
            654321,
            null,
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"),
            0);
    when(this.codeVerificationService.createFakeChallenge()).thenReturn(fakeChallenge);

    StartPasswordRecoveryRequest request =
        new StartPasswordRecoveryRequest("userWithoutEmail", EMAIL_PARAMETERS);

    StartPasswordRecoveryResult result = this.useCase.startPasswordRecovery(request);

    assertEquals(
        "fake-456", result.challengeId(), "Should return fake challenge ID when user has no email");
  }

  @Test
  void testSuccessfulRecoveryStartReturnsChallenge() {

    User user = mock(User.class);
    when(user.email()).thenReturn("user@example.com");
    when(user.toDisplayName()).thenReturn("Test User");
    when(this.userService.findByUsername("validUser")).thenReturn(Optional.of(user));

    CodeVerificationChallenge challenge =
        new CodeVerificationChallenge(
            "challenge-789",
            789012,
            new PasswordRecoverPayload("validUser"),
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"),
            0);
    when(this.codeVerificationService.startChallenge(any(PasswordRecoverPayload.class)))
        .thenReturn(challenge);

    TemplateEmailMessage message = mock(TemplateEmailMessage.class);
    TemplateEmailMessage.Builder builder = mock(TemplateEmailMessage.Builder.class);
    when(message.toBuilder()).thenReturn(builder);
    when(message.data()).thenReturn(Map.of());
    when(builder.data(any())).thenReturn(builder);
    when(builder.build()).thenReturn(message);

    StartPasswordRecoveryRequest request =
        new StartPasswordRecoveryRequest("validUser", EMAIL_PARAMETERS);

    StartPasswordRecoveryResult result = this.useCase.startPasswordRecovery(request);

    assertEquals(
        "challenge-789",
        result.challengeId(),
        "Should return actual challenge ID for valid user with email");
  }

  @Test
  void testSuccessfulRecoverySendsEmail() throws EmailSendException {

    User user = mock(User.class);
    when(user.email()).thenReturn("user@example.com");
    when(user.toDisplayName()).thenReturn("Test User");
    when(this.userService.findByUsername("validUser")).thenReturn(Optional.of(user));

    CodeVerificationChallenge challenge =
        new CodeVerificationChallenge(
            "challenge-789",
            789012,
            new PasswordRecoverPayload("validUser"),
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"),
            0);
    when(this.codeVerificationService.startChallenge(any(PasswordRecoverPayload.class)))
        .thenReturn(challenge);

    TemplateEmailMessage message = mock(TemplateEmailMessage.class);
    TemplateEmailMessage.Builder builder = mock(TemplateEmailMessage.Builder.class);
    when(message.toBuilder()).thenReturn(builder);
    when(message.data()).thenReturn(Map.of());
    when(builder.data(any())).thenReturn(builder);
    when(builder.build()).thenReturn(message);

    StartPasswordRecoveryRequest request =
        new StartPasswordRecoveryRequest("validUser", EMAIL_PARAMETERS);

    this.useCase.startPasswordRecovery(request);

    verify(this.emailService).send(any());
  }

  @Test
  void testEmailSendFailureThrowsException() throws EmailSendException {

    User user = mock(User.class);
    when(user.email()).thenReturn("user@example.com");
    when(user.toDisplayName()).thenReturn("Test User");
    when(this.userService.findByUsername("validUser")).thenReturn(Optional.of(user));

    CodeVerificationChallenge challenge =
        new CodeVerificationChallenge(
            "challenge-789",
            789012,
            new PasswordRecoverPayload("validUser"),
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"),
            0);
    when(this.codeVerificationService.startChallenge(any(PasswordRecoverPayload.class)))
        .thenReturn(challenge);

    TemplateEmailMessage message = mock(TemplateEmailMessage.class);
    TemplateEmailMessage.Builder builder = mock(TemplateEmailMessage.Builder.class);
    when(message.toBuilder()).thenReturn(builder);
    when(message.data()).thenReturn(Map.of());
    when(builder.data(any())).thenReturn(builder);
    when(builder.build()).thenReturn(message);

    doThrow(new EmailSendException("Failed to send")).when(this.emailService).send(any());

    StartPasswordRecoveryRequest request =
        new StartPasswordRecoveryRequest("validUser", EMAIL_PARAMETERS);

    assertThrows(
        StartPasswordRecoveryException.class,
        () -> {
          this.useCase.startPasswordRecovery(request);
        },
        "Should throw StartPasswordRecoveryException when email send fails");
  }

  @Test
  void testVerifyUserServiceCalled() {

    when(this.userService.findByUsername("testuser")).thenReturn(Optional.empty());

    CodeVerificationChallenge fakeChallenge =
        new CodeVerificationChallenge(
            "fake-123",
            123456,
            null,
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"),
            0);
    when(this.codeVerificationService.createFakeChallenge()).thenReturn(fakeChallenge);

    StartPasswordRecoveryRequest request =
        new StartPasswordRecoveryRequest("testuser", EMAIL_PARAMETERS);

    this.useCase.startPasswordRecovery(request);

    verify(this.userService).findByUsername("testuser");
  }

  @Test
  void testVerifyCodeVerificationServiceCalledForValidUser() {

    User user = mock(User.class);
    when(user.email()).thenReturn("user@example.com");
    when(user.toDisplayName()).thenReturn("Test User");
    when(this.userService.findByUsername("validUser")).thenReturn(Optional.of(user));

    CodeVerificationChallenge challenge =
        new CodeVerificationChallenge(
            "challenge-789",
            789012,
            new PasswordRecoverPayload("validUser"),
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"),
            0);
    when(this.codeVerificationService.startChallenge(any(PasswordRecoverPayload.class)))
        .thenReturn(challenge);

    TemplateEmailMessage message = mock(TemplateEmailMessage.class);
    TemplateEmailMessage.Builder builder = mock(TemplateEmailMessage.Builder.class);
    when(message.toBuilder()).thenReturn(builder);
    when(message.data()).thenReturn(Map.of());
    when(builder.data(any())).thenReturn(builder);
    when(builder.build()).thenReturn(message);

    StartPasswordRecoveryRequest request =
        new StartPasswordRecoveryRequest("validUser", EMAIL_PARAMETERS);

    this.useCase.startPasswordRecovery(request);

    verify(this.codeVerificationService).startChallenge(any(PasswordRecoverPayload.class));
  }

  @Test
  void testVerifyCodeVerificationServiceCalledForInvalidUser() {

    when(this.userService.findByUsername(anyString())).thenReturn(Optional.empty());

    CodeVerificationChallenge fakeChallenge =
        new CodeVerificationChallenge(
            "fake-123",
            123456,
            null,
            Instant.parse("2025-01-01T10:00:00Z"),
            Instant.parse("2025-01-01T10:15:00Z"),
            0);
    when(this.codeVerificationService.createFakeChallenge()).thenReturn(fakeChallenge);

    StartPasswordRecoveryRequest request =
        new StartPasswordRecoveryRequest("unknown", EMAIL_PARAMETERS);

    this.useCase.startPasswordRecovery(request);

    verify(this.codeVerificationService).createFakeChallenge();
  }
}

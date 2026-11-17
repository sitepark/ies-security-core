package com.sitepark.ies.security.core.usecase.emailcode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.exception.AuthFactorNotAllowedException;
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
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class StartEmailCodeSetupUseCaseTest {

  private UserService userService;
  private AccessControl accessControl;
  private AuthenticationPolicyService policyService;
  private CodeVerificationService codeVerificationService;
  private EmailCodeSender sender;
  private StartEmailCodeSetupUseCase useCase;

  @BeforeEach
  void setUp() {
    this.userService = mock();
    this.accessControl = mock();
    this.policyService = mock();
    this.codeVerificationService = mock();
    this.sender = mock();
    this.useCase =
        new StartEmailCodeSetupUseCase(
            this.userService,
            this.accessControl,
            this.policyService,
            this.codeVerificationService,
            this.sender);
  }

  @Test
  void testNotAllowed() {
    doThrow(new AuthFactorNotAllowedException(AuthFactorType.EMAIL_CODE))
        .when(this.policyService)
        .requireFactorAllowed(AuthFactorType.EMAIL_CODE);
    assertThrows(
        AuthFactorNotAllowedException.class,
        () -> this.useCase.startEmailCodeSetup("7"),
        "a switched-off e-mail code must not be set up");
  }

  @Test
  void testAccessDenied() {
    assertThrows(
        AccessDeniedException.class,
        () -> this.useCase.startEmailCodeSetup("7"),
        "setting up must need access");
  }

  @Test
  void testNoEmailAddress() {
    when(this.accessControl.isEmailCodeManageable("7")).thenReturn(true);
    when(this.userService.findById("7"))
        .thenReturn(Optional.of(User.builder().id("7").username("peter").lastName("Pan").build()));
    assertThrows(
        NoEmailAddressException.class,
        () -> this.useCase.startEmailCodeSetup("7"),
        "a user without e-mail address cannot use the e-mail code");
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testStart() {
    User user =
        User.builder().id("7").username("peter").lastName("Pan").email("p@example.org").build();
    when(this.accessControl.isEmailCodeManageable("7")).thenReturn(true);
    when(this.userService.findById("7")).thenReturn(Optional.of(user));
    Instant now = Instant.parse("2026-11-17T10:00:00Z");
    CodeVerificationChallenge challenge =
        new CodeVerificationChallenge(
            "c-1",
            123_456,
            new EmailCodeSetupPayload("7", "p@example.org"),
            now,
            now.plusSeconds(600),
            0);
    when(this.codeVerificationService.startChallenge(any())).thenReturn(challenge);

    assertEquals("c-1", this.useCase.startEmailCodeSetup("7"), "the challenge id is returned");
    verify(this.sender).send(user, "p@example.org", challenge);
  }
}

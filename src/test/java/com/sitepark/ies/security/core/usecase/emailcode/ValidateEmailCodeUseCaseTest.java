package com.sitepark.ies.security.core.usecase.emailcode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.exception.EmailCodeNotRequiredException;
import com.sitepark.ies.security.core.domain.service.AuthenticationPolicyService;
import com.sitepark.ies.security.core.domain.service.EmailCodeService;
import com.sitepark.ies.security.core.domain.value.AuthenticationFailureReason;
import com.sitepark.ies.security.core.domain.value.AuthenticationRequirement;
import com.sitepark.ies.security.core.domain.value.AuthenticationResult;
import com.sitepark.ies.security.core.domain.value.PartialAuthenticationState;
import com.sitepark.ies.security.core.domain.value.PolicyDecision;
import com.sitepark.ies.security.core.port.TotpAuthenticationProcessStore;
import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.User;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
class ValidateEmailCodeUseCaseTest {

  private final User user = User.builder().id("7").username("peter").lastName("Pan").build();

  private TotpAuthenticationProcessStore store;
  private EmailCodeService emailCodeService;
  private AuthenticationPolicyService policyService;
  private ValidateEmailCodeUseCase useCase;

  @BeforeEach
  void setUp() {
    this.store = mock();
    this.emailCodeService = mock();
    this.policyService = mock();
    when(this.policyService.decidePasswordLogin(any(), anyBoolean()))
        .thenReturn(new PolicyDecision.Allowed(null));
    this.useCase =
        new ValidateEmailCodeUseCase(this.store, this.emailCodeService, this.policyService);
  }

  private void state(AuthenticationRequirement requirement, String challengeId) {
    when(this.store.retrieve("p-1"))
        .thenReturn(
            Optional.of(
                new PartialAuthenticationState(
                    this.user,
                    AuthMethod.PASSWORD,
                    List.of(requirement),
                    Instant.parse("2026-11-17T10:00:00Z"),
                    "purpose",
                    challengeId)));
  }

  @Test
  void testNotRequired() {
    this.state(AuthenticationRequirement.TOTP_CODE_REQUIRED, null);
    assertThrows(
        EmailCodeNotRequiredException.class,
        () -> this.useCase.validateEmailCode("p-1", 123_456),
        "a login without e-mail code must not accept one");
  }

  @Test
  void testWrongCode() {
    this.state(AuthenticationRequirement.EMAIL_CODE_REQUIRED, "c-1");
    assertEquals(
        AuthenticationResult.failure(),
        this.useCase.validateEmailCode("p-1", 1),
        "a wrong code must fail");
  }

  @Test
  void testSuccess() {
    this.state(AuthenticationRequirement.EMAIL_CODE_REQUIRED, "c-1");
    when(this.emailCodeService.verify(this.user, "c-1", 123_456)).thenReturn(true);
    assertEquals(
        AuthenticationResult.success(this.user, "purpose"),
        this.useCase.validateEmailCode("p-1", 123_456),
        "a valid code completes the login");
  }

  @Test
  void testRefusedByPolicy() {
    this.state(AuthenticationRequirement.EMAIL_CODE_REQUIRED, "c-1");
    when(this.emailCodeService.verify(this.user, "c-1", 123_456)).thenReturn(true);
    when(this.policyService.decidePasswordLogin(this.user, true))
        .thenReturn(new PolicyDecision.Denied(AuthenticationFailureReason.PASSKEY_REQUIRED));
    assertEquals(
        AuthenticationResult.failure(AuthenticationFailureReason.PASSKEY_REQUIRED),
        this.useCase.validateEmailCode("p-1", 123_456),
        "the policy may refuse after the code");
  }
}

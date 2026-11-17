package com.sitepark.ies.security.core.usecase.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.service.AuthenticationPolicyService;
import com.sitepark.ies.security.core.domain.value.AuthenticationFailureReason;
import com.sitepark.ies.security.core.domain.value.AuthenticationPolicyLevel;
import com.sitepark.ies.security.core.domain.value.AuthenticationRequirement;
import com.sitepark.ies.security.core.domain.value.AuthenticationResult;
import com.sitepark.ies.security.core.domain.value.PartialAuthenticationState;
import com.sitepark.ies.security.core.domain.value.PolicyDecision;
import com.sitepark.ies.security.core.domain.value.PolicyNotice;
import com.sitepark.ies.security.core.port.AuthenticationAttemptLimiter;
import com.sitepark.ies.security.core.port.LdapAuthenticator;
import com.sitepark.ies.security.core.port.TotpAuthenticationProcessStore;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.AuthFactor;
import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.Identity;
import com.sitepark.ies.sharedkernel.security.PasswordEncoder;
import com.sitepark.ies.sharedkernel.security.User;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("PMD.ExcessiveImports")
class PasswordAuthenticationUseCaseTest {

  private AuthenticationPolicyService policyService;

  private final Clock fixedClock =
      Clock.fixed(Instant.parse("2026-11-17T10:00:00Z"), ZoneOffset.UTC);

  private UserService userService;
  private LdapAuthenticator ldapAuthenticator;
  private PasswordEncoder passwordEncoder;
  private AuthenticationAttemptLimiter loginAttemptLimiter;
  private TotpAuthenticationProcessStore authenticationProcessStore;
  private PasswordAuthenticationUseCase useCase;

  @BeforeEach
  void setUp() {
    userService = mock();
    ldapAuthenticator = mock();
    passwordEncoder = mock();
    loginAttemptLimiter = mock();
    authenticationProcessStore = mock();

    this.policyService = mock();

    when(this.policyService.decidePasswordLogin(any(), anyBoolean()))
        .thenReturn(new PolicyDecision.Allowed(null));
    // by default every factor is allowed and a TOTP secret leads to the TOTP step
    when(this.policyService.isFactorAllowed(any())).thenReturn(true);
    when(this.policyService.hasAllowedSecondFactor(any()))
        .thenAnswer(inv -> inv.<User>getArgument(0).authFactors().contains(AuthFactor.TOTP));

    useCase =
        new PasswordAuthenticationUseCase(
            fixedClock,
            userService,
            ldapAuthenticator,
            passwordEncoder,
            loginAttemptLimiter,
            authenticationProcessStore,
            policyService);
  }

  @Test
  void testFailureLoginLimiterExceeded() {
    when(this.loginAttemptLimiter.accept(any())).thenReturn(false);
    when(this.loginAttemptLimiter.getAttemptCount(any())).thenReturn(10);
    when(this.loginAttemptLimiter.getMaxAttempts()).thenReturn(7);

    assertEquals(
        AuthenticationResult.failure(),
        this.useCase.passwordAuthentication("username", "password", "purpose"),
        "Expected failure due to exceeded login attempts");
  }

  @Test
  void testFailureUserNotFound() {
    when(this.loginAttemptLimiter.accept(any())).thenReturn(true);
    when(this.userService.findByUsername(any())).thenReturn(Optional.empty());

    assertEquals(
        AuthenticationResult.failure(),
        this.useCase.passwordAuthentication("username", "password", "purpose"),
        "Expected failure due to exceeded login attempts");
  }

  @Test
  void testFailureUserHasNoPassword() {
    when(this.loginAttemptLimiter.accept(any())).thenReturn(true);
    User user = User.builder().id("1").username("peterpan").lastName("Pan").build();
    when(this.userService.findByUsername(any())).thenReturn(Optional.of(user));
    when(this.passwordEncoder.matches(any(), any())).thenReturn(false);

    assertEquals(
        AuthenticationResult.failure(),
        this.useCase.passwordAuthentication("username", "password", "purpose"),
        "Expected failure due to user having no newPassword");
  }

  @Test
  void testFailurePasswordNotMatch() {
    when(this.loginAttemptLimiter.accept(any())).thenReturn(true);
    User user = User.builder().id("1").username("peterpan").lastName("Pan").build();
    when(this.userService.findByUsername(any())).thenReturn(Optional.of(user));
    when(this.userService.getPasswordHash(any())).thenReturn(Optional.of("hashedPassword"));
    when(this.passwordEncoder.matches(any(), any())).thenReturn(false);

    assertEquals(
        AuthenticationResult.failure(),
        this.useCase.passwordAuthentication("username", "password", "purpose"),
        "Expected failure due to newPassword not matching");
  }

  @Test
  void testSuccessWithoutAdditionalFactor() {
    when(this.loginAttemptLimiter.accept(any())).thenReturn(true);
    User user = User.builder().id("1").username("username").lastName("Test").build();
    when(this.userService.findByUsername(any())).thenReturn(Optional.of(user));
    when(this.userService.getPasswordHash(any())).thenReturn(Optional.of("hashedPassword"));
    when(this.passwordEncoder.matches(any(), any())).thenReturn(true);

    assertEquals(
        AuthenticationResult.success(user, "purpose"),
        this.useCase.passwordAuthentication("username", "password", "purpose"),
        "Expected successful authentication without additional factors");
  }

  @Test
  void testSuccessWithUpgradePassword() {
    when(this.loginAttemptLimiter.accept(any())).thenReturn(true);
    User user = User.builder().id("1").username("username").lastName("Test").build();
    when(this.userService.findByUsername("username")).thenReturn(Optional.of(user));
    when(this.userService.getPasswordHash(any())).thenReturn(Optional.of("hashedPassword"));
    when(this.passwordEncoder.matches(any(), any())).thenReturn(true);
    when(this.passwordEncoder.upgradeEncoding(any())).thenReturn(true);
    when(this.passwordEncoder.encode(any())).thenReturn("hash");

    this.useCase.passwordAuthentication("username", "password", "purpose");

    verify(this.userService).upgradePasswordHash("username", "hash");
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testPartialWithRequiredFactor() {
    when(this.loginAttemptLimiter.accept(any())).thenReturn(true);
    User user =
        User.builder()
            .id("1")
            .username("username")
            .lastName("Test")
            .authFactors(AuthFactor.TOTP)
            .build();
    when(this.userService.findByUsername(any())).thenReturn(Optional.of(user));
    when(this.userService.getPasswordHash(any())).thenReturn(Optional.of("hashedPassword"));
    when(this.passwordEncoder.matches(any(), any())).thenReturn(true);
    when(this.authenticationProcessStore.store(any())).thenReturn("123");
    List<AuthenticationRequirement> requirements =
        List.of(AuthenticationRequirement.TOTP_CODE_REQUIRED);

    AuthenticationResult expectedResult = AuthenticationResult.partial("123", requirements);

    PartialAuthenticationState expectedPartialState =
        new PartialAuthenticationState(
            user, AuthMethod.PASSWORD, requirements, Instant.now(this.fixedClock), "purpose");

    assertEquals(
        expectedResult,
        this.useCase.passwordAuthentication("username", "password", "purpose"),
        "Expected successful authentication without additional factors");

    verify(this.authenticationProcessStore).store(expectedPartialState);
  }

  @Test
  void testFailureLdapAuthentication() {
    when(this.loginAttemptLimiter.accept(any())).thenReturn(true);
    User user =
        User.builder()
            .id("1")
            .username("username")
            .lastName("Test")
            .identity(Identity.ldap("1", "cn=username,ou=users,dc=example,dc=com"))
            .build();
    when(this.userService.findByUsername("username")).thenReturn(Optional.of(user));
    when(this.ldapAuthenticator.authenticate(any(), any())).thenReturn(false);

    assertEquals(
        AuthenticationResult.failure(),
        this.useCase.passwordAuthentication("username", "password", "purpose"),
        "Expected failure due to newPassword not matching");
  }

  @Test
  void testSuccessLdapAuthentication() {
    when(this.loginAttemptLimiter.accept(any())).thenReturn(true);
    User user =
        User.builder()
            .id("1")
            .username("username")
            .lastName("Test")
            .identity(Identity.ldap("1", "cn=username,ou=users,dc=example,dc=com"))
            .build();
    when(this.userService.findByUsername("username")).thenReturn(Optional.of(user));
    when(this.ldapAuthenticator.authenticate(any(), any())).thenReturn(true);

    assertEquals(
        AuthenticationResult.success(user, "purpose"),
        this.useCase.passwordAuthentication("username", "password", "purpose"),
        "Expected successful LDAP authentication");
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testRefusedByPolicyAfterCorrectPassword() {
    when(this.loginAttemptLimiter.accept(any())).thenReturn(true);
    User user =
        User.builder()
            .id("1")
            .username("username")
            .lastName("Test")
            .authFactors(AuthFactor.TOTP)
            .build();
    when(this.userService.findByUsername(any())).thenReturn(Optional.of(user));
    when(this.userService.getPasswordHash(any())).thenReturn(Optional.of("hashedPassword"));
    when(this.passwordEncoder.matches(any(), any())).thenReturn(true);
    when(this.policyService.decidePasswordLogin(user, true))
        .thenReturn(new PolicyDecision.Denied(AuthenticationFailureReason.PASSKEY_REQUIRED));

    assertEquals(
        AuthenticationResult.failure(AuthenticationFailureReason.PASSKEY_REQUIRED),
        this.useCase.passwordAuthentication("username", "password", "purpose"),
        "the policy must refuse the password");
    verify(this.authenticationProcessStore, never()).store(any());
    verify(this.loginAttemptLimiter, never()).onFailedLogin(any());
  }

  @Test
  void testSuccessWithNotice() {
    when(this.loginAttemptLimiter.accept(any())).thenReturn(true);
    User user = User.builder().id("1").username("username").lastName("Test").build();
    when(this.userService.findByUsername(any())).thenReturn(Optional.of(user));
    when(this.userService.getPasswordHash(any())).thenReturn(Optional.of("hashedPassword"));
    when(this.passwordEncoder.matches(any(), any())).thenReturn(true);
    PolicyNotice notice =
        new PolicyNotice(
            AuthenticationPolicyLevel.SECOND_FACTOR, Instant.parse("2026-12-01T00:00:00Z"));
    when(this.policyService.decidePasswordLogin(user, false))
        .thenReturn(new PolicyDecision.Allowed(notice));

    assertEquals(
        AuthenticationResult.success(user, "purpose").withPolicyNotice(notice),
        this.useCase.passwordAuthentication("username", "password", "purpose"),
        "the notice must be passed on");
  }

  @Test
  void testSwitchedOffTotpIsNotAsked() {
    when(this.loginAttemptLimiter.accept(any())).thenReturn(true);
    User user =
        User.builder()
            .id("1")
            .username("username")
            .lastName("Test")
            .authFactors(AuthFactor.TOTP)
            .build();
    when(this.userService.findByUsername(any())).thenReturn(Optional.of(user));
    when(this.userService.getPasswordHash(any())).thenReturn(Optional.of("hashedPassword"));
    when(this.passwordEncoder.matches(any(), any())).thenReturn(true);
    when(this.policyService.hasAllowedSecondFactor(user)).thenReturn(false);

    assertEquals(
        AuthenticationResult.success(user, "purpose"),
        this.useCase.passwordAuthentication("username", "password", "purpose"),
        "a switched-off TOTP must not be asked for");
  }
}

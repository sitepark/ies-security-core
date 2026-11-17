package com.sitepark.ies.security.core.domain.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.exception.AuthFactorNotAllowedException;
import com.sitepark.ies.security.core.domain.exception.AuthenticationPolicyNotAllowedException;
import com.sitepark.ies.security.core.domain.value.AuthFactorType;
import com.sitepark.ies.security.core.domain.value.AuthenticationFailureReason;
import com.sitepark.ies.security.core.domain.value.AuthenticationPolicy;
import com.sitepark.ies.security.core.domain.value.AuthenticationPolicyLevel;
import com.sitepark.ies.security.core.domain.value.PolicyDecision;
import com.sitepark.ies.security.core.domain.value.PolicyNotice;
import com.sitepark.ies.security.core.domain.value.SystemAuthenticationSettings;
import com.sitepark.ies.security.core.port.AuthenticationPolicyRepository;
import com.sitepark.ies.security.core.port.SystemAuthenticationSettingsProvider;
import com.sitepark.ies.sharedkernel.security.AuthFactor;
import com.sitepark.ies.sharedkernel.security.User;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuthenticationPolicyServiceTest {

  private static final Instant NOW = Instant.parse("2026-11-16T10:00:00Z");
  private static final Instant LATER = NOW.plusSeconds(3600);
  private static final Instant EARLIER = NOW.minusSeconds(3600);

  private final User user = User.builder().id("7").username("peter").lastName("Pan").build();

  private AuthenticationPolicyRepository repository;
  private SystemAuthenticationSettingsProvider settingsProvider;
  private AuthenticationPolicyService service;

  @BeforeEach
  void setUp() {
    this.repository = mock();
    this.settingsProvider = mock();
    when(this.settingsProvider.get()).thenReturn(SystemAuthenticationSettings.DEFAULT);
    this.service =
        new AuthenticationPolicyService(
            this.repository, this.settingsProvider, Clock.fixed(NOW, ZoneOffset.UTC));
  }

  private void settings(AuthenticationPolicy minimum, AuthFactorType... allowed) {
    when(this.settingsProvider.get())
        .thenReturn(new SystemAuthenticationSettings(Set.of(allowed), minimum));
  }

  private void policy(AuthenticationPolicyLevel level, Instant deadline) {
    when(this.repository.get("7"))
        .thenReturn(Optional.of(new AuthenticationPolicy(level, deadline)));
  }

  @Test
  void testGetPolicyDefaultsToNone() {
    when(this.repository.get("7")).thenReturn(Optional.empty());
    assertEquals(
        AuthenticationPolicy.NONE, this.service.getPolicy("7"), "missing policy must be NONE");
  }

  @Test
  void testNoneAllowsPassword() {
    when(this.repository.get("7")).thenReturn(Optional.empty());
    assertEquals(
        new PolicyDecision.Allowed(null),
        this.service.decidePasswordLogin(this.user, false),
        "NONE must allow the password alone");
  }

  @Test
  void testSecondFactorFollowsAllowed() {
    this.policy(AuthenticationPolicyLevel.SECOND_FACTOR, EARLIER);
    assertEquals(
        new PolicyDecision.Allowed(null),
        this.service.decidePasswordLogin(this.user, true),
        "a following second factor must meet SECOND_FACTOR");
  }

  @Test
  void testSecondFactorMissingBeforeDeadline() {
    this.policy(AuthenticationPolicyLevel.SECOND_FACTOR, LATER);
    assertEquals(
        new PolicyDecision.Allowed(
            new PolicyNotice(AuthenticationPolicyLevel.SECOND_FACTOR, LATER)),
        this.service.decidePasswordLogin(this.user, false),
        "a missing second factor must be reminded before the deadline");
  }

  @Test
  void testSecondFactorMissingAfterDeadline() {
    this.policy(AuthenticationPolicyLevel.SECOND_FACTOR, EARLIER);
    assertEquals(
        new PolicyDecision.Denied(AuthenticationFailureReason.SECOND_FACTOR_REQUIRED),
        this.service.decidePasswordLogin(this.user, false),
        "a missing second factor must be refused after the deadline");
  }

  @Test
  void testExternalLoginHasNoSecondFactor() {
    this.policy(AuthenticationPolicyLevel.SECOND_FACTOR, EARLIER);
    assertEquals(
        new PolicyDecision.Denied(AuthenticationFailureReason.SECOND_FACTOR_REQUIRED),
        this.service.decideExternalLogin(this.user),
        "an external login must not meet SECOND_FACTOR");
  }

  @Test
  void testPasskeyBeforeDeadlineWithSecondFactor() {
    this.policy(AuthenticationPolicyLevel.PASSKEY, LATER);
    assertEquals(
        new PolicyDecision.Allowed(new PolicyNotice(AuthenticationPolicyLevel.PASSKEY, LATER)),
        this.service.decidePasswordLogin(this.user, true),
        "PASSKEY must remind before the deadline even with a second factor");
  }

  @Test
  void testPasskeyAfterDeadlineRefusesPasswordWithSecondFactor() {
    this.policy(AuthenticationPolicyLevel.PASSKEY, EARLIER);
    assertEquals(
        new PolicyDecision.Denied(AuthenticationFailureReason.PASSKEY_REQUIRED),
        this.service.decidePasswordLogin(this.user, true),
        "PASSKEY must refuse the password after the deadline even with a second factor");
  }

  @Test
  void testPasswordRecoveryAllowedWithoutPolicy() {
    when(this.repository.get("7")).thenReturn(Optional.empty());
    assertTrue(
        this.service.isPasswordRecoveryAllowed(this.user), "recovery must be allowed by NONE");
  }

  @Test
  void testPasswordRecoveryAllowedForSecondFactor() {
    this.policy(AuthenticationPolicyLevel.SECOND_FACTOR, EARLIER);
    assertTrue(
        this.service.isPasswordRecoveryAllowed(this.user),
        "recovery must be allowed by SECOND_FACTOR, the login still asks for the factor");
  }

  @Test
  void testPasswordRecoveryAllowedBeforePasskeyDeadline() {
    this.policy(AuthenticationPolicyLevel.PASSKEY, LATER);
    assertTrue(
        this.service.isPasswordRecoveryAllowed(this.user),
        "recovery must be allowed before the passkey deadline");
  }

  @Test
  void testPasswordRecoveryRefusedAfterPasskeyDeadline() {
    this.policy(AuthenticationPolicyLevel.PASSKEY, EARLIER);
    assertFalse(
        this.service.isPasswordRecoveryAllowed(this.user),
        "recovery must be refused after the passkey deadline");
  }

  @Test
  void testSystemMinimumAppliesToUserWithoutPolicy() {
    when(this.repository.get("7")).thenReturn(Optional.empty());
    this.settings(
        new AuthenticationPolicy(AuthenticationPolicyLevel.SECOND_FACTOR, EARLIER),
        AuthFactorType.TOTP,
        AuthFactorType.PASSKEY);
    assertEquals(
        new PolicyDecision.Denied(AuthenticationFailureReason.SECOND_FACTOR_REQUIRED),
        this.service.decidePasswordLogin(this.user, false),
        "the minimum policy of the installation must apply to every user");
  }

  @Test
  void testStricterUserPolicyWins() {
    this.policy(AuthenticationPolicyLevel.PASSKEY, EARLIER);
    this.settings(
        new AuthenticationPolicy(AuthenticationPolicyLevel.SECOND_FACTOR, LATER),
        AuthFactorType.TOTP,
        AuthFactorType.PASSKEY);
    assertEquals(
        AuthenticationPolicyLevel.PASSKEY,
        this.service.getEffectivePolicy("7").level(),
        "the stricter policy of the user must win");
  }

  @Test
  void testSameLevelEarlierDeadlineWins() {
    this.policy(AuthenticationPolicyLevel.SECOND_FACTOR, LATER);
    this.settings(
        new AuthenticationPolicy(AuthenticationPolicyLevel.SECOND_FACTOR, EARLIER),
        AuthFactorType.TOTP);
    assertEquals(
        EARLIER,
        this.service.getEffectivePolicy("7").deadline(),
        "with the same level the earlier deadline must win");
  }

  @Test
  void testSwitchedOffTotpIsNoSecondFactor() {
    User withTotp =
        User.builder()
            .id("7")
            .username("peter")
            .lastName("Pan")
            .authFactors(AuthFactor.TOTP)
            .build();
    this.settings(AuthenticationPolicy.NONE, AuthFactorType.PASSKEY);
    assertFalse(
        this.service.hasAllowedSecondFactor(withTotp),
        "a TOTP secret must not count while TOTP is switched off");
  }

  @Test
  void testRequireFactorAllowed() {
    this.settings(AuthenticationPolicy.NONE, AuthFactorType.TOTP);
    assertThrows(
        AuthFactorNotAllowedException.class,
        () -> this.service.requireFactorAllowed(AuthFactorType.PASSKEY),
        "a switched-off factor must be refused");
  }

  @Test
  void testRequirePolicyAllowed() {
    this.settings(AuthenticationPolicy.NONE, AuthFactorType.TOTP);
    assertThrows(
        AuthenticationPolicyNotAllowedException.class,
        () ->
            this.service.requirePolicyAllowed(
                new AuthenticationPolicy(AuthenticationPolicyLevel.PASSKEY, null)),
        "a passkey policy must be refused while passkeys are switched off");
  }
}

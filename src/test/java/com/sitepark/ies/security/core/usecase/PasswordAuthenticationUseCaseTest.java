package com.sitepark.ies.security.core.usecase;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.value.AuthenticationRequirement;
import com.sitepark.ies.security.core.domain.value.PartialAuthenticationState;
import com.sitepark.ies.security.core.port.AuthenticationAttemptLimiter;
import com.sitepark.ies.security.core.port.AuthenticationProcessStore;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.security.core.usecase.authentication.AuthenticationResult;
import com.sitepark.ies.sharedkernel.security.AuthFactor;
import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.PasswordEncoder;
import com.sitepark.ies.sharedkernel.security.User;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PasswordAuthenticationUseCaseTest {

  private final Clock fixedClock =
      Clock.fixed(OffsetDateTime.now().toInstant(), ZoneId.systemDefault());

  private UserService userService;
  private PasswordEncoder passwordEncoder;
  private AuthenticationAttemptLimiter loginAttemptLimiter;
  private AuthenticationProcessStore authenticationProcessStore;
  private PasswordAuthenticationUseCase useCase;

  @BeforeEach
  void setUp() {
    userService = mock(UserService.class);
    passwordEncoder = mock(PasswordEncoder.class);
    loginAttemptLimiter = mock(AuthenticationAttemptLimiter.class);
    authenticationProcessStore = mock(AuthenticationProcessStore.class);

    useCase =
        new PasswordAuthenticationUseCase(
            fixedClock,
            userService,
            passwordEncoder,
            loginAttemptLimiter,
            authenticationProcessStore);
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
    User user = mock();
    when(this.userService.findByUsername(any())).thenReturn(Optional.of(user));
    when(this.passwordEncoder.matches(any(), any())).thenReturn(false);

    assertEquals(
        AuthenticationResult.failure(),
        this.useCase.passwordAuthentication("username", "password", "purpose"),
        "Expected failure due to user having no password");
  }

  @Test
  void testFailurePasswordNotMatch() {
    when(this.loginAttemptLimiter.accept(any())).thenReturn(true);
    User user = mock();
    when(this.userService.findByUsername(any())).thenReturn(Optional.of(user));
    when(this.userService.getPasswordHash(any())).thenReturn(Optional.of("hashedPassword"));
    when(this.passwordEncoder.matches(any(), any())).thenReturn(false);

    assertEquals(
        AuthenticationResult.failure(),
        this.useCase.passwordAuthentication("username", "password", "purpose"),
        "Expected failure due to password not matching");
  }

  @Test
  void testSuccessWithoutAdditionalFactor() {
    when(this.loginAttemptLimiter.accept(any())).thenReturn(true);
    User user = User.builder().id("1").username("username").lastName("Test").build();
    when(this.userService.findByUsername(any())).thenReturn(Optional.of(user));
    when(this.userService.getPasswordHash(any())).thenReturn(Optional.of("hashedPassword"));
    when(this.passwordEncoder.matches(any(), any())).thenReturn(true);

    assertEquals(
        AuthenticationResult.success(user),
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
    AuthenticationRequirement[] requirements =
        new AuthenticationRequirement[] {AuthenticationRequirement.TOTP_CODE_REQUIRED};

    AuthenticationResult expectedResult = AuthenticationResult.partial("123", requirements);

    PartialAuthenticationState expectedPartialState =
        new PartialAuthenticationState(
            user, AuthMethod.PASSWORD, requirements, Instant.now(this.fixedClock));

    assertEquals(
        expectedResult,
        this.useCase.passwordAuthentication("username", "password", "purpose"),
        "Expected successful authentication without additional factors");

    verify(this.authenticationProcessStore).store(expectedPartialState);
  }
}

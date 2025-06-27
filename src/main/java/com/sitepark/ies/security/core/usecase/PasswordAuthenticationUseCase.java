package com.sitepark.ies.security.core.usecase;

import com.sitepark.ies.security.core.domain.entity.AuthenticatedUser;
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
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import jakarta.inject.Inject;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PasswordAuthenticationUseCase {

  private final UserService userService;

  private final PasswordEncoder passwordEncoder;

  private final AuthenticationAttemptLimiter loginAttemptLimiter;

  private final AuthenticationProcessStore authenticationProcessStore;

  private final Logger LOGGER = LogManager.getLogger();

  @Inject
  @SuppressFBWarnings("EI_EXPOSE_REP2")
  public PasswordAuthenticationUseCase(
      UserService userService,
      PasswordEncoder passwordEncoder,
      AuthenticationAttemptLimiter loginAttemptLimiter,
      AuthenticationProcessStore authenticationSessionStore) {
    this.userService = userService;
    this.passwordEncoder = passwordEncoder;
    this.loginAttemptLimiter = loginAttemptLimiter;
    this.authenticationProcessStore = authenticationSessionStore;
  }

  public AuthenticationResult passwordAuthentication(
      String username, String password, String purpose) {

    if (!isLoginAllowed(username, purpose)) {
      return AuthenticationResult.failure();
    }

    Optional<User> optUser = validateUser(username, password);
    if (optUser.isEmpty()) {
      return AuthenticationResult.failure();
    }
    User user = optUser.get();

    upgradePasswordHashIfNeeded(user, password);

    if (user.getAuthFactors().length == 0) {
      return AuthenticationResult.success(AuthenticatedUser.fromUser(user));
    }

    List<AuthenticationRequirement> requirements = getLoginRequirements(user);

    String authProcessId =
        this.authenticationProcessStore.store(
            new PartialAuthenticationState(
                user,
                AuthMethod.PASSWORD,
                requirements.toArray(AuthenticationRequirement[]::new),
                OffsetDateTime.now()));

    return AuthenticationResult.partial(
        authProcessId, requirements.toArray(AuthenticationRequirement[]::new));
  }

  private boolean isLoginAllowed(String username, String purpose) {
    if (!this.loginAttemptLimiter.accept(username)) {
      // log only if the number of failed attempts is not too high
      int doLogCount =
          (this.loginAttemptLimiter.getAttemptCount(username)
              - this.loginAttemptLimiter.getMaxAttempts());
      int maxDoLogCount = 5;
      if (doLogCount < maxDoLogCount && LOGGER.isWarnEnabled()) {
        LOGGER.warn(
            "Login attempt for user '{}' with purpose '{}' is not allowed due to too many failed"
                + " attempts. Blocked until: {}{}",
            username,
            purpose,
            this.loginAttemptLimiter.getBlockedUntil(username),
            (doLogCount + 1) == maxDoLogCount ? " (stop logging)" : "");
      }
      this.loginAttemptLimiter.onFailedLogin(username);
      return false;
    }
    return true;
  }

  private Optional<User> validateUser(String username, String password) {
    Optional<User> optUser = this.userService.findByUsername(username);
    if (optUser.isEmpty()) {
      this.loginAttemptLimiter.onFailedLogin(username);
      return Optional.empty();
    }
    User user = optUser.get();
    if (!passwordEncoder.matches(password, user.getPasswordHash())) {
      this.loginAttemptLimiter.onFailedLogin(username);
      return Optional.empty();
    }
    this.loginAttemptLimiter.onSuccessfulLogin(username);
    return Optional.of(user);
  }

  private void upgradePasswordHashIfNeeded(User user, String password) {
    if (passwordEncoder.upgradeEncoding(user.getPasswordHash())) {
      String upgradedHash = passwordEncoder.encode(password);
      this.userService.upgradePasswordHash(user.getUsername(), upgradedHash);
    }
  }

  private List<AuthenticationRequirement> getLoginRequirements(User user) {
    List<AuthenticationRequirement> requirements = new ArrayList<>();
    for (AuthFactor authFactor : user.getAuthFactors()) {
      if (Objects.requireNonNull(authFactor) == AuthFactor.TOTP) {
        requirements.add(AuthenticationRequirement.TOTP_CODE_REQUIRED);
      } else {
        throw new IllegalArgumentException("Unsupported auth factor: " + authFactor);
      }
    }
    return requirements;
  }
}

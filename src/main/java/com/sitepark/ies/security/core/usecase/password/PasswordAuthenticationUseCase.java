package com.sitepark.ies.security.core.usecase.password;

import com.sitepark.ies.security.core.domain.value.AuthenticationRequirement;
import com.sitepark.ies.security.core.domain.value.AuthenticationResult;
import com.sitepark.ies.security.core.domain.value.PartialAuthenticationState;
import com.sitepark.ies.security.core.port.AuthenticationAttemptLimiter;
import com.sitepark.ies.security.core.port.LdapAuthenticator;
import com.sitepark.ies.security.core.port.TotpAuthenticationProcessStore;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.AuthFactor;
import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.InternalIdentity;
import com.sitepark.ies.sharedkernel.security.LdapIdentity;
import com.sitepark.ies.sharedkernel.security.PasswordEncoder;
import com.sitepark.ies.sharedkernel.security.User;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PasswordAuthenticationUseCase {

  private final Clock clock;

  private final UserService userService;

  private final LdapAuthenticator ldapAuthenticator;

  private final PasswordEncoder passwordEncoder;

  private final AuthenticationAttemptLimiter loginAttemptLimiter;

  private final TotpAuthenticationProcessStore authenticationProcessStore;

  private static final Logger LOGGER = LogManager.getLogger();

  @Inject
  @SuppressFBWarnings("EI_EXPOSE_REP2")
  public PasswordAuthenticationUseCase(
      Clock clock,
      UserService userService,
      LdapAuthenticator ldapAuthenticator,
      PasswordEncoder passwordEncoder,
      AuthenticationAttemptLimiter loginAttemptLimiter,
      TotpAuthenticationProcessStore authenticationSessionStore) {
    this.clock = clock;
    this.userService = userService;
    this.ldapAuthenticator = ldapAuthenticator;
    this.passwordEncoder = passwordEncoder;
    this.loginAttemptLimiter = loginAttemptLimiter;
    this.authenticationProcessStore = authenticationSessionStore;
  }

  public AuthenticationResult passwordAuthentication(
      String username, String password, String purpose) {

    if (!isLoginAllowed(username, purpose)) {
      return AuthenticationResult.failure();
    }

    Optional<User> optUser = loadUser(username);
    if (optUser.isEmpty()) {
      return AuthenticationResult.failure();
    }

    User user = optUser.get();
    if (!authenticateUser(user, password)) {
      return AuthenticationResult.failure();
    }

    return buildAuthenticationResult(user, purpose);
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

  private Optional<User> loadUser(String username) {
    Optional<User> optUser = this.userService.findByUsername(username);
    if (optUser.isEmpty()) {
      this.loginAttemptLimiter.onFailedLogin(username);
      return Optional.empty();
    }
    return optUser;
  }

  private boolean authenticateUser(User user, String password) {
    return switch (user.identity()) {
      case InternalIdentity ignored -> authenticateInternalUserAndUpgradePassword(user, password);
      case LdapIdentity ldap -> authenticateLdapIdentity(user.username(), ldap, password);
      default -> {
        if (LOGGER.isWarnEnabled()) {
          LOGGER.warn(
              "Unsupported identity type '{}' for user '{}'",
              user.identity().getClass().getName(),
              user.username());
        }
        yield false;
      }
    };
  }

  private AuthenticationResult buildAuthenticationResult(User user, String purpose) {

    if (user.authFactors().isEmpty()) {
      return AuthenticationResult.success(user, purpose);
    }

    AuthenticationRequirement[] requirements = getLoginRequirements(user);

    String authProcessId =
        this.authenticationProcessStore.store(
            new PartialAuthenticationState(
                user, AuthMethod.PASSWORD, requirements, Instant.now(this.clock), purpose));

    return AuthenticationResult.partial(authProcessId, requirements);
  }

  private boolean authenticateInternalUserAndUpgradePassword(User user, String password) {

    Optional<String> passwordHash = this.userService.getPasswordHash(user.id());
    if (passwordHash.isEmpty()) {
      this.loginAttemptLimiter.onFailedLogin(user.username());
      return false;
    }
    if (!passwordEncoder.matches(password, passwordHash.get())) {
      this.loginAttemptLimiter.onFailedLogin(user.username());
      return false;
    }

    if (passwordEncoder.upgradeEncoding(passwordHash.get())) {
      String upgradedHash = passwordEncoder.encode(password);
      this.userService.upgradePasswordHash(user.username(), upgradedHash);
    }

    this.loginAttemptLimiter.onSuccessfulLogin(user.username());

    return true;
  }

  private boolean authenticateLdapIdentity(
      String username, LdapIdentity identity, String password) {

    if (!this.ldapAuthenticator.authenticate(identity, password)) {
      this.loginAttemptLimiter.onFailedLogin(username);
      return false;
    }

    this.loginAttemptLimiter.onSuccessfulLogin(username);
    return true;
  }

  private AuthenticationRequirement[] getLoginRequirements(User user) {
    List<AuthenticationRequirement> requirements = new ArrayList<>();
    for (AuthFactor authFactor : user.authFactors()) {
      if (authFactor == AuthFactor.TOTP) {
        requirements.add(AuthenticationRequirement.TOTP_CODE_REQUIRED);
      } else {
        throw new IllegalStateException(
            "Unsupported auth factor: " + authFactor + " for user: " + user.username());
      }
    }

    return requirements.toArray(AuthenticationRequirement[]::new);
  }
}

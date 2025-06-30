package com.sitepark.ies.security.core.usecase;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import com.sitepark.ies.security.core.domain.exception.AccessTokenExpiredException;
import com.sitepark.ies.security.core.domain.exception.AccessTokenNotActiveException;
import com.sitepark.ies.security.core.domain.exception.AccessTokenRevokedException;
import com.sitepark.ies.security.core.domain.exception.InvalidAccessTokenException;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

public class AuthenticateByToken {

  private final Clock clock;

  private final AccessTokenRepository accessTokenRepository;

  private final UserService userService;

  @Inject
  protected AuthenticateByToken(
      Clock clock, AccessTokenRepository accessTokenRepository, UserService userService) {
    this.clock = clock;
    this.accessTokenRepository = accessTokenRepository;
    this.userService = userService;
  }

  public User authenticateByToken(String token) {

    Optional<AccessToken> accessTokenOpt = this.accessTokenRepository.getByToken(token);
    if (accessTokenOpt.isEmpty()) {
      throw new InvalidAccessTokenException("Token not found");
    }

    AccessToken accessToken = accessTokenOpt.get();
    if (!accessToken.active()) {
      throw new AccessTokenNotActiveException();
    }
    if (accessToken.revoked()) {
      throw new AccessTokenRevokedException();
    }
    this.checkExpirationDate(accessToken.expiresAt());

    Optional<User> user = this.userService.findById(accessToken.user());
    if (user.isEmpty()) {
      throw new InvalidAccessTokenException("User " + accessToken.user() + " not found");
    }

    return user.get();
  }

  public void checkExpirationDate(Instant expiredAt) {

    if (expiredAt == null) {
      return;
    }

    Instant now = Instant.now(this.clock);
    if (expiredAt.isBefore(now)) {
      throw new AccessTokenExpiredException(expiredAt);
    }
  }
}

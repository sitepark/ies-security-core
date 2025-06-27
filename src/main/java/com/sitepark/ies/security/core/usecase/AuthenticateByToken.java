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
import java.time.OffsetDateTime;
import java.util.Optional;

public class AuthenticateByToken {

  private final AccessTokenRepository accessTokenRepository;

  private final UserService userService;

  @Inject
  protected AuthenticateByToken(
      AccessTokenRepository accessTokenRepository, UserService userService) {
    this.accessTokenRepository = accessTokenRepository;
    this.userService = userService;
  }

  public User authenticateByToken(String token) {

    Optional<AccessToken> accessTokenOptinal = this.accessTokenRepository.getByToken(token);
    if (accessTokenOptinal.isEmpty()) {
      throw new InvalidAccessTokenException("Token not found");
    }

    AccessToken accessToken = accessTokenOptinal.get();
    if (!accessToken.isActive()) {
      throw new AccessTokenNotActiveException();
    }
    if (accessToken.isRevoked()) {
      throw new AccessTokenRevokedException();
    }
    this.checkExpirationDate(accessToken.getExpiresAt());

    Optional<User> user = this.userService.findById(accessToken.getUser());
    if (user.isEmpty()) {
      throw new InvalidAccessTokenException("User " + accessToken.getUser() + " not found");
    }

    return user.get();
  }

  public void checkExpirationDate(Optional<OffsetDateTime> expiredAt) {

    if (expiredAt.isEmpty()) {
      return;
    }

    OffsetDateTime now = OffsetDateTime.now();
    if (expiredAt.get().isBefore(now)) {
      throw new AccessTokenExpiredException(expiredAt.get());
    }
  }
}

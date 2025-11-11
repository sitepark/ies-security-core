package com.sitepark.ies.security.core.usecase.token;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import com.sitepark.ies.security.core.domain.exception.AccessTokenExpiredException;
import com.sitepark.ies.security.core.domain.exception.AccessTokenNotActiveException;
import com.sitepark.ies.security.core.domain.exception.AccessTokenRevokedException;
import com.sitepark.ies.security.core.domain.exception.InvalidAccessTokenException;
import com.sitepark.ies.security.core.domain.value.TokenType;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.security.core.port.PermissionLoader;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.Authentication;
import com.sitepark.ies.sharedkernel.security.Permission;
import com.sitepark.ies.sharedkernel.security.ServiceAuthentication;
import com.sitepark.ies.sharedkernel.security.User;
import com.sitepark.ies.sharedkernel.security.UserAuthentication;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

public class TokenAuthenticationUseCase {

  private final Clock clock;

  private final AccessTokenRepository accessTokenRepository;

  private final PermissionLoader permissionLoader;

  private final UserService userService;

  @Inject
  protected TokenAuthenticationUseCase(
      Clock clock,
      AccessTokenRepository accessTokenRepository,
      PermissionLoader permissionLoader,
      UserService userService) {
    this.clock = clock;
    this.accessTokenRepository = accessTokenRepository;
    this.permissionLoader = permissionLoader;
    this.userService = userService;
  }

  public Authentication authenticateByToken(String token) {

    AccessToken accessToken = loadToken(token);

    return switch (accessToken.tokenType()) {
      case TokenType.PRIVATE, TokenType.IMPERSONATION ->
          this.createUserBasedAuthentication(accessToken);
      case TokenType.SERVICE -> this.createTokenBasedAuthentication(accessToken);
    };
  }

  private AccessToken loadToken(String token) {
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

    this.accessTokenRepository.touch(accessToken.id());

    return accessToken;
  }

  private UserAuthentication createUserBasedAuthentication(AccessToken accessToken) {
    Optional<User> user = this.userService.findById(accessToken.userId());
    if (user.isEmpty()) {
      throw new InvalidAccessTokenException("User " + accessToken.userId() + " not found");
    }

    List<Permission> permissions = this.permissionLoader.loadByUser(user.get().id());

    return UserAuthentication.builder().user(user.get()).permissions(permissions).build();
  }

  private ServiceAuthentication createTokenBasedAuthentication(AccessToken accessToken) {
    return ServiceAuthentication.builder()
        .name(accessToken.name())
        .permissions(accessToken.permissions())
        .build();
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

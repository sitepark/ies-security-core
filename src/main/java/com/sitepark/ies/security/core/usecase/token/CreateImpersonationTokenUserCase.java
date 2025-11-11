package com.sitepark.ies.security.core.usecase.token;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import com.sitepark.ies.security.core.domain.exception.InvalidAccessTokenException;
import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.value.TokenType;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.security.core.port.TokenService;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import jakarta.inject.Inject;
import java.time.Clock;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CreateImpersonationTokenUserCase {

  private final AccessTokenRepository repository;

  private final AccessControl accessControl;

  private final TokenService tokenService;

  private final UserService userService;

  private final Clock clock;

  private static final Logger LOGGER = LogManager.getLogger();

  @Inject
  protected CreateImpersonationTokenUserCase(
      AccessTokenRepository repository,
      AccessControl accessControl,
      TokenService tokenService,
      UserService userService,
      Clock clock) {
    this.repository = repository;
    this.accessControl = accessControl;
    this.tokenService = tokenService;
    this.userService = userService;
    this.clock = clock;
  }

  public CreateTokenResult createImpersonationToken(CreateImpersonationTokenRequest request) {

    if (!this.accessControl.isImpersonationTokensManageable()) {
      throw new AccessDeniedException("Not allowed manage impersonation tokens");
    }

    if (this.userService.findById(request.userId()).isEmpty()) {
      throw new InvalidAccessTokenException("user " + request.userId() + " not found");
    }

    String token = this.tokenService.generateToken();
    String tokenDigest = this.tokenService.digestToken(token);

    AccessToken accessToken =
        AccessToken.builder()
            .userId(request.userId())
            .name(request.name())
            .createdAt(this.clock.instant())
            .expiresAt(request.expiresAt())
            .tokenType(TokenType.IMPERSONATION)
            .build();

    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("create access-token: {}", accessToken);
    }

    AccessToken entity = this.repository.create(accessToken, tokenDigest);

    return new CreateTokenResult(entity, token);
  }
}

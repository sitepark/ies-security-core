package com.sitepark.ies.security.core.usecase.token;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
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

public class CreateServiceTokenUserCase {

  private final AccessTokenRepository repository;

  private final AccessControl accessControl;

  private final TokenService tokenService;

  private final Clock clock;

  private static final Logger LOGGER = LogManager.getLogger();

  @Inject
  protected CreateServiceTokenUserCase(
      AccessTokenRepository repository,
      AccessControl accessControl,
      TokenService tokenService,
      UserService userService,
      Clock clock) {
    this.repository = repository;
    this.accessControl = accessControl;
    this.tokenService = tokenService;
    this.clock = clock;
  }

  public CreateTokenResult createServiceToken(CreateServiceTokenRequest request) {

    if (!this.accessControl.isImpersonationTokensManageable()) {
      throw new AccessDeniedException("Not allowed manage service tokens");
    }

    String token = this.tokenService.generateToken();
    String tokenDigest = this.tokenService.digestToken(token);

    AccessToken accessToken =
        AccessToken.builder()
            .name(request.name())
            .permissions(request.permissions())
            .createdAt(this.clock.instant())
            .expiresAt(request.expiresAt())
            .tokenType(TokenType.SERVICE)
            .build();

    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("create access-token: {}", accessToken);
    }

    AccessToken entity = this.repository.create(accessToken, tokenDigest);

    return new CreateTokenResult(entity, token);
  }
}

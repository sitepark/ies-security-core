package com.sitepark.ies.security.core.usecase.token;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import com.sitepark.ies.security.core.domain.exception.InvalidAccessTokenException;
import com.sitepark.ies.security.core.domain.value.TokenType;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.security.core.port.TokenService;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.Authentication;
import com.sitepark.ies.sharedkernel.security.UserAuthentication;
import jakarta.inject.Inject;
import jakarta.inject.Provider;
import java.time.Clock;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CreatePrivateTokenUserCase {

  private final AccessTokenRepository repository;

  private final Provider<Authentication> authenticationProvider;

  private final TokenService tokenService;

  private final UserService userService;

  private final Clock clock;

  private static final Logger LOGGER = LogManager.getLogger();

  @Inject
  protected CreatePrivateTokenUserCase(
      Provider<Authentication> authenticationProvider,
      AccessTokenRepository repository,
      TokenService tokenService,
      UserService userService,
      Clock clock) {
    this.authenticationProvider = authenticationProvider;
    this.repository = repository;
    this.tokenService = tokenService;
    this.userService = userService;
    this.clock = clock;
  }

  public CreateTokenResult createPrivateToken(CreatePrivateTokenRequest request) {

    Authentication authentication = this.authenticationProvider.get();
    if (!(authentication instanceof UserAuthentication userAuthentication)) {
      throw new AccessDeniedException("Only user based authenticated users can create tokens");
    }

    String userId = userAuthentication.user().id();

    if (this.userService.findById(userId).isEmpty()) {
      throw new InvalidAccessTokenException("user " + userId + " not found");
    }

    String token = this.tokenService.generateToken();
    String tokenDigest = this.tokenService.digestToken(token);

    AccessToken accessToken =
        AccessToken.builder()
            .userId(userId)
            .name(request.name())
            .createdAt(this.clock.instant())
            .expiresAt(request.expiresAt())
            .tokenType(TokenType.PRIVATE)
            .build();

    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("create access-token: {}", accessToken);
    }

    AccessToken entity = this.repository.create(accessToken, tokenDigest);

    return new CreateTokenResult(entity, token);
  }
}

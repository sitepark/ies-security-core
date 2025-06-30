package com.sitepark.ies.security.core.usecase;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import com.sitepark.ies.security.core.domain.exception.InvalidAccessTokenException;
import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import jakarta.inject.Inject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CreateImpersonationToken {

  private final AccessTokenRepository repository;

  private final AccessControl accessControl;

  private final UserService userService;

  private static final Logger LOGGER = LogManager.getLogger();

  @Inject
  protected CreateImpersonationToken(
      AccessTokenRepository repository, AccessControl accessControl, UserService userService) {
    this.repository = repository;
    this.accessControl = accessControl;
    this.userService = userService;
  }

  public AccessToken createPersonalAccessToken(AccessToken accessToken) {

    AccessToken accessTokenToCreate = accessToken.toBuilder().impersonation(true).build();

    if (!this.accessControl.isImpersonationTokensManageable()) {
      throw new AccessDeniedException("Not allowed manage impersonation tokens");
    }

    if (this.userService.findById(accessToken.user()).isEmpty()) {
      throw new InvalidAccessTokenException("user " + accessToken.user() + " not found");
    }

    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("create: {}", accessTokenToCreate);
    }

    return this.repository.create(accessTokenToCreate);
  }
}

package com.sitepark.ies.security.core.usecase.token;

import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import jakarta.inject.Inject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RevokeImpersonationTokenUseCase {

  private final AccessTokenRepository repository;

  private final AccessControl accessControl;

  private static final Logger LOGGER = LogManager.getLogger();

  @Inject
  protected RevokeImpersonationTokenUseCase(
      AccessTokenRepository repository, AccessControl accessControl) {
    this.repository = repository;
    this.accessControl = accessControl;
  }

  public void revokeImpersonationToken(String id) {

    if (!this.accessControl.isImpersonationTokensManageable()) {
      throw new AccessDeniedException("Not allowed manage impersonation tokens");
    }

    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("revoke impersonation token: {}", id);
    }

    this.repository.revoke(id);
  }
}

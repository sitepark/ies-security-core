package com.sitepark.ies.security.core.usecase.token;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import jakarta.inject.Inject;
import java.util.List;

public class GetImpersonationTokensUseCase {

  private final AccessTokenRepository accessTokenRepository;

  private final AccessControl accessControl;

  @Inject
  protected GetImpersonationTokensUseCase(
      AccessTokenRepository accessTokenRepository, AccessControl accessControl) {
    this.accessTokenRepository = accessTokenRepository;
    this.accessControl = accessControl;
  }

  public List<AccessToken> getImpersonationTokens() {

    if (!this.accessControl.isGetImpersonationTokensAllowed()) {
      throw new AccessDeniedException("Not allowed to get impersonation tokens");
    }

    return this.accessTokenRepository.getImpersonationTokens();
  }
}

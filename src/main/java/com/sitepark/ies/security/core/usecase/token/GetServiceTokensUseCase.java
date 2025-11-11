package com.sitepark.ies.security.core.usecase.token;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import jakarta.inject.Inject;
import java.util.List;

public class GetServiceTokensUseCase {

  private final AccessTokenRepository accessTokenRepository;

  private final AccessControl accessControl;

  @Inject
  protected GetServiceTokensUseCase(
      AccessTokenRepository accessTokenRepository, AccessControl accessControl) {
    this.accessTokenRepository = accessTokenRepository;
    this.accessControl = accessControl;
  }

  public List<AccessToken> getServiceTokens() {

    if (!this.accessControl.isGetServiceTokensAllowed()) {
      throw new AccessDeniedException("Not allowed to get service tokens");
    }

    return this.accessTokenRepository.getServiceTokens();
  }
}

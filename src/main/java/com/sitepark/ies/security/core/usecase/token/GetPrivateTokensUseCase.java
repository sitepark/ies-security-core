package com.sitepark.ies.security.core.usecase.token;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.port.AccessTokenRepository;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.Authentication;
import com.sitepark.ies.sharedkernel.security.UserAuthentication;
import jakarta.inject.Inject;
import jakarta.inject.Provider;
import java.util.List;

public class GetPrivateTokensUseCase {

  private final Provider<Authentication> authenticationProvider;

  private final AccessTokenRepository accessTokenRepository;

  private final AccessControl accessControl;

  @Inject
  protected GetPrivateTokensUseCase(
      Provider<Authentication> authenticationProvider,
      AccessTokenRepository accessTokenRepository,
      AccessControl accessControl) {
    this.authenticationProvider = authenticationProvider;
    this.accessTokenRepository = accessTokenRepository;
    this.accessControl = accessControl;
  }

  public List<AccessToken> getPrivateTokens() {

    Authentication authentication = this.authenticationProvider.get();
    if (!(authentication instanceof UserAuthentication userAuthentication)) {
      throw new AccessDeniedException(
          "Only user based authenticated users can get the private tokens");
    }

    String userId = userAuthentication.user().id();

    if (!this.accessControl.isGetPrivateTokensAllowed(userAuthentication.user().id())) {
      throw new AccessDeniedException("Not allowed to get service tokens");
    }

    return this.accessTokenRepository.getPrivateTokens(userId);
  }
}

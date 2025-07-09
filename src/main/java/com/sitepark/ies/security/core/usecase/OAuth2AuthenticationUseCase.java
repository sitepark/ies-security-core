package com.sitepark.ies.security.core.usecase;

import com.sitepark.ies.security.core.domain.value.OAuth2User;
import com.sitepark.ies.security.core.port.OAuth2Authenticator;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.security.core.usecase.authentication.AuthenticationResult;
import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.AuthProviderType;
import com.sitepark.ies.sharedkernel.security.AuthenticationContext;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;
import java.util.Optional;

public class OAuth2AuthenticationUseCase {

  private final OAuth2Authenticator oAuth2Authenticator;

  private final UserService userService;

  @Inject
  protected OAuth2AuthenticationUseCase(
      OAuth2Authenticator oAuth2Authenticator, UserService userService) {
    this.oAuth2Authenticator = oAuth2Authenticator;
    this.userService = userService;
  }

  public AuthenticationResult oauth2Authentication(
      AuthProviderType providerType, String applicationName, String code) {
    OAuth2User oAuth2User =
        this.oAuth2Authenticator.authenticate(providerType, applicationName, code);
    if (oAuth2User == null) {
      return AuthenticationResult.failure();
    }

    User user =
        User.builder()
            .id(oAuth2User.id())
            .username(oAuth2User.email())
            .firstName(oAuth2User.givenName())
            .lastName(oAuth2User.familyName())
            .email(oAuth2User.email())
            .build();

    AuthenticationContext context =
        new AuthenticationContext(providerType, null, AuthMethod.OAUTH2, oAuth2User.id());

    Optional<User> syncedUser = this.userService.syncAuthenticatedUser(context, user);

    return syncedUser
        .map(value -> AuthenticationResult.success(value, applicationName))
        .orElseGet(AuthenticationResult::failure);
  }
}

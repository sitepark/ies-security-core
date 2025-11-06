package com.sitepark.ies.security.core.usecase.oidc;

import com.sitepark.ies.security.core.domain.value.AuthenticationResult;
import com.sitepark.ies.security.core.domain.value.OidcUser;
import com.sitepark.ies.security.core.port.OidcAuthenticator;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.AuthProviderType;
import com.sitepark.ies.sharedkernel.security.AuthenticationContext;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;
import java.util.Optional;

public class OidcAuthenticationUseCase {

  private final OidcAuthenticator oidcAuthenticator;

  private final UserService userService;

  @Inject
  protected OidcAuthenticationUseCase(
      OidcAuthenticator oAuth2Authenticator, UserService userService) {
    this.oidcAuthenticator = oAuth2Authenticator;
    this.userService = userService;
  }

  public AuthenticationResult oidcAuthentication(
      AuthProviderType providerType, String applicationName, String code) {
    OidcUser oidcUser = this.oidcAuthenticator.authenticate(providerType, applicationName, code);
    if (oidcUser == null) {
      return AuthenticationResult.failure();
    }

    User user =
        User.builder()
            .id(oidcUser.id())
            .username(oidcUser.email())
            .firstName(oidcUser.givenName())
            .lastName(oidcUser.familyName())
            .email(oidcUser.email())
            .build();

    AuthenticationContext context =
        new AuthenticationContext(providerType, null, AuthMethod.OAUTH2, oidcUser.id());

    Optional<User> syncedUser = this.userService.syncAuthenticatedUser(context, user);

    return syncedUser
        .map(value -> AuthenticationResult.success(value, applicationName))
        .orElseGet(AuthenticationResult::failure);
  }
}

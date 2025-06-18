package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.exception.AuthenticationFailedException;
import com.sitepark.ies.sharedkernel.security.Authentication;
import jakarta.inject.Inject;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/** */
public class AuthenticationManager {

  private final List<AuthenticationProvider> authenticationProviderSet;

  private static final Comparator<AuthenticationProvider> PRIORITY_COMPARATOR =
      Comparator.comparingInt(AuthenticationProvider::priority);

  @Inject
  protected AuthenticationManager(Set<AuthenticationProvider> authenticationProviderSet) {
    this.authenticationProviderSet =
        authenticationProviderSet.stream().sorted(PRIORITY_COMPARATOR).collect(Collectors.toList());
  }

  public Authentication authenticate(Authentication authentication) {

    try {
      Authentication result = this.doAuthenticate(authentication);
      result.eraseCredentials();
      return result;
    } catch (AuthenticationFailedException e) {
      e.getAuthentication().eraseCredentials();
      throw e;
    }
  }

  private Authentication doAuthenticate(Authentication authentication) {

    Authentication next = null;

    for (AuthenticationProvider provider : this.authenticationProviderSet) {
      if (provider.supports(authentication)) {
        Authentication result = provider.authenticat(authentication);
        if (result.isAuthenticated()) {
          return result;
        } else {
          next = result;
        }
      }
    }

    throw new AuthenticationFailedException(next, "Uncomplete authentication chain");
  }
}

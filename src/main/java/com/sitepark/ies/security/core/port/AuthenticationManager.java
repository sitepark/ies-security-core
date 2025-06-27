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
    return this.doAuthenticate(authentication);
  }

  private Authentication doAuthenticate(Authentication authentication) {

    for (AuthenticationProvider provider : this.authenticationProviderSet) {
      if (provider.supports(authentication)) {
        return provider.authenticat(authentication);
      }
    }

    throw new AuthenticationFailedException("Uncomplete authentication chain");
  }
}

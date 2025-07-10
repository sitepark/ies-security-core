package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.value.OidcUser;
import com.sitepark.ies.sharedkernel.security.AuthProviderType;

@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface OidcAuthenticator {
  OidcUser authenticate(AuthProviderType providerType, String applicationName, String code);
}

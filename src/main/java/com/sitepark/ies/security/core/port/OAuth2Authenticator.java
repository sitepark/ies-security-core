package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.value.OAuth2User;
import com.sitepark.ies.sharedkernel.security.AuthProviderType;

@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface OAuth2Authenticator {
  OAuth2User authenticate(AuthProviderType providerType, String applicationName, String code);
}

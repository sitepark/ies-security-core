package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.value.SystemAuthenticationSettings;

/** Provides the login settings of the installation. */
@FunctionalInterface
public interface SystemAuthenticationSettingsProvider {

  SystemAuthenticationSettings get();
}

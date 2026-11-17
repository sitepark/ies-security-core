package com.sitepark.ies.security.core.usecase.policy;

import com.sitepark.ies.security.core.domain.value.SystemAuthenticationSettings;
import com.sitepark.ies.security.core.port.SystemAuthenticationSettingsProvider;
import jakarta.inject.Inject;

/**
 * Returns the login settings of the installation. They are public: the login form needs them before
 * anybody is logged in, and they reveal nothing about a user.
 */
public class GetSystemAuthenticationSettingsUseCase {

  private final SystemAuthenticationSettingsProvider settingsProvider;

  @Inject
  protected GetSystemAuthenticationSettingsUseCase(
      SystemAuthenticationSettingsProvider settingsProvider) {
    this.settingsProvider = settingsProvider;
  }

  public SystemAuthenticationSettings getSystemAuthenticationSettings() {
    return this.settingsProvider.get();
  }
}

package com.sitepark.ies.security.core.domain.service;

import com.sitepark.ies.security.core.port.WebAuthnProvider;
import com.sitepark.ies.sharedkernel.security.Authentication;
import com.sitepark.ies.sharedkernel.security.UserAuthentication;
import jakarta.inject.Inject;
import jakarta.inject.Provider;

public class AccessControl {

  private final Provider<Authentication> authenticationProvider;

  private final WebAuthnProvider webAuthnProvider;

  @Inject
  protected AccessControl(
      Provider<Authentication> authenticationProvider, WebAuthnProvider webAuthnProvider) {
    this.authenticationProvider = authenticationProvider;
    this.webAuthnProvider = webAuthnProvider;
  }

  public boolean isImpersonationTokensManageable() {
    return this.authenticationProvider.get() != null
        && this.authenticationProvider.get().hasFullAccess();
  }

  public boolean isGenerateTotpUrlAllowed(String userId) {
    return this.isAuthenticatedUserOrHasFullAccess(userId);
  }

  public boolean isRemoveTotpSecretAllowed(String userId) {
    return this.isAuthenticatedUserOrHasFullAccess(userId);
  }

  public boolean isWebAuthnRegistrationAllowed(String userId) {
    return this.isAuthenticatedUserOrHasFullAccess(userId);
  }

  public boolean isWebAuthnGetRegisteredCredentialsAllowed(String userId) {
    return this.isAuthenticatedUserOrHasFullAccess(userId);
  }

  public boolean isWebAuthnRemoveRegisteredCredentialsAllowed(String id) {
    String userId = this.webAuthnProvider.getUserIdById(id);

    return userId != null && this.isWebAuthnGetRegisteredCredentialsAllowed(userId);
  }

  public boolean isSetPasswordAllowed(final String userId) {
    return this.isAuthenticatedUserOrHasFullAccess(userId);
  }

  public boolean isGetPrivateTokensAllowed(String userId) {
    return this.isFullAccess() || this.isAuthenticatedUser(userId);
  }

  public boolean isGetServiceTokensAllowed() {
    return this.isFullAccess();
  }

  public boolean isGetImpersonationTokensAllowed() {
    return this.isFullAccess();
  }

  private boolean isFullAccess() {
    return this.authenticationProvider.get().hasFullAccess();
  }

  public boolean isAuthenticatedUser(String userId) {
    Authentication authentication = this.authenticationProvider.get();

    return (authentication instanceof UserAuthentication userAuthentication)
        && userAuthentication.user().id().equals(userId);
  }

  private boolean isAuthenticatedUserOrHasFullAccess(String userId) {

    Authentication authentication = this.authenticationProvider.get();

    boolean fullAccess = authentication != null && authentication.hasFullAccess();
    boolean owner =
        (authentication instanceof UserAuthentication userAuthentication)
            && userAuthentication.user().id().equals(userId);

    return fullAccess || owner;
  }
}

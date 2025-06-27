package com.sitepark.ies.security.core.usecase.authentication;

import com.sitepark.ies.sharedkernel.security.AuthMethod;

public class AuthenticationInfo {
  private final AuthMethod[] authMethods;

  @SuppressWarnings("PMD.UseVarargs")
  public AuthenticationInfo(AuthMethod[] authMethods) {
    this.authMethods = authMethods != null ? authMethods : new AuthMethod[] {};
  }

  public AuthMethod[] getAuthMethods() {
    return authMethods.clone();
  }
}

package com.sitepark.ies.security.core.usecase.authentication;

import com.sitepark.ies.sharedkernel.security.AuthMethod;
import java.util.Collections;
import java.util.List;

public class AuthenticationInfo {
  private final List<AuthMethod> authMethods;

  public AuthenticationInfo(List<AuthMethod> authMethods) {
    this.authMethods =
        authMethods != null ? List.copyOf(authMethods) : List.copyOf(Collections.emptyList());
  }

  public List<AuthMethod> getAuthMethods() {
    return authMethods;
  }
}

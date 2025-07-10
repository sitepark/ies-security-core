package com.sitepark.ies.security.core.domain.value;

import com.sitepark.ies.sharedkernel.security.AuthMethod;
import java.util.Collections;
import java.util.List;

public record AuthenticationInfo(List<AuthMethod> authMethods) {
  public AuthenticationInfo(List<AuthMethod> authMethods) {
    this.authMethods =
        authMethods != null ? List.copyOf(authMethods) : List.copyOf(Collections.emptyList());
  }
}

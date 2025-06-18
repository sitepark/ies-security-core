package com.sitepark.ies.security.core.port;

import com.sitepark.ies.sharedkernel.security.Authentication;

public interface AuthenticationProvider {

  public int priority();

  public Authentication authenticat(Authentication authentication);

  public boolean supports(Authentication authentication);
}

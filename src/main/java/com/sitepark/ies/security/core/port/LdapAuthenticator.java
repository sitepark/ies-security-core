package com.sitepark.ies.security.core.port;

import com.sitepark.ies.sharedkernel.security.LdapIdentity;

@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface LdapAuthenticator {
  boolean authenticate(LdapIdentity identity, String password);
}

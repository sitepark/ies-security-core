package com.sitepark.ies.security.core.domain.entity;

import com.sitepark.ies.sharedkernel.security.Authentication;

public interface UserBasedAuthentication extends Authentication {
  AuthenticatedUser getUser();
}

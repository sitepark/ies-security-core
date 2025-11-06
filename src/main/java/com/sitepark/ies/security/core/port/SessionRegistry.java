package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.entity.Session;
import com.sitepark.ies.sharedkernel.security.UserAuthentication;

public interface SessionRegistry {

  Session create(UserAuthentication authentication, String purpose);

  Session getSession(String sessionId);

  void close(String sessionId);

  void touch(String sessionId);
}

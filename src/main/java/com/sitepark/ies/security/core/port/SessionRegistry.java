package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.entity.Session;
import com.sitepark.ies.security.core.domain.entity.UserBasedAuthentication;

public interface SessionRegistry {

  Session create(UserBasedAuthentication authentication);

  Session getSession(String sessionId);

  void close(String sessionId);

  void touch(String sessionId);
}

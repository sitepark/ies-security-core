package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.entity.Session;
import com.sitepark.ies.sharedkernel.security.Authentication;

public interface SessionRegistry {

  Session create(Authentication authentication);

  Session getSession(long sessionId);

  void close(long sessionId);

  void touch(long sessionId);
}

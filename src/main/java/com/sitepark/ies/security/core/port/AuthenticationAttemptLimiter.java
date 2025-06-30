package com.sitepark.ies.security.core.port;

import java.time.Instant;

public interface AuthenticationAttemptLimiter {

  boolean accept(String username);

  Instant getBlockedUntil(String username);

  int getMaxAttempts();

  int getAttemptCount(String username);

  void onSuccessfulLogin(String username);

  void onFailedLogin(String username);
}

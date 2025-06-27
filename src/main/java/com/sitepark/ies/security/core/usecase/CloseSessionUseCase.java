package com.sitepark.ies.security.core.usecase;

import com.sitepark.ies.security.core.port.SessionRegistry;
import jakarta.inject.Inject;

public class CloseSessionUseCase {

  private final SessionRegistry sessionRegistry;

  @Inject
  protected CloseSessionUseCase(SessionRegistry sessionRegistry) {
    this.sessionRegistry = sessionRegistry;
  }

  public void closeSession(String sessionId) {
    this.sessionRegistry.close(sessionId);
  }
}

package com.sitepark.ies.security.core.usecase.session;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.sitepark.ies.security.core.port.SessionRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CloseSessionUseCaseTest {

  private SessionRegistry sessionRegistry;

  private CloseSessionUseCase useCase;

  @BeforeEach
  void setUp() {
    this.sessionRegistry = mock(SessionRegistry.class);
    this.useCase = new CloseSessionUseCase(sessionRegistry);
  }

  @Test
  void testCloseSession() {
    this.useCase.closeSession("123");
    verify(this.sessionRegistry).close("123");
  }
}

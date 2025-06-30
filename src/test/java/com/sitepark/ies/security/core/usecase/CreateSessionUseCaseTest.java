package com.sitepark.ies.security.core.usecase;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.entity.AuthenticatedUser;
import com.sitepark.ies.security.core.domain.entity.Session;
import com.sitepark.ies.security.core.port.PermissionLoader;
import com.sitepark.ies.security.core.port.SessionRegistry;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CreateSessionUseCaseTest {

  private SessionRegistry sessionRegistry;
  private PermissionLoader permissionLoader;

  private CreateSessionUseCase useCase;

  @BeforeEach
  void setUp() {
    this.sessionRegistry = mock();
    this.permissionLoader = mock();

    this.useCase = new CreateSessionUseCase(sessionRegistry, permissionLoader);
  }

  @Test
  void testCreateSession() {

    AuthenticatedUser user =
        AuthenticatedUser.builder()
            .id("234")
            .username("peterpan")
            .firstName("Peter")
            .lastName("pan")
            .build();

    Session session = mock();
    when(session.id()).thenReturn("123");
    when(this.sessionRegistry.create(any())).thenReturn(session);
    when(this.permissionLoader.loadByUser(user.id())).thenReturn(List.of());

    assertEquals(
        "123",
        useCase.createSession(user, "purpose"),
        "Session ID should match the mocked session ID");
  }
}

package com.sitepark.ies.security.core.domain.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

class SessionTimeoutExceptionTest {

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testMessageWithoutSessionId() {
    SessionTimeoutException e = new SessionTimeoutException(123456789L);
    assertEquals("Session timeout", e.getMessage(), "unexpected message");
    assertFalse(e.getMessage().contains("123456789"), "message must not contain the session id");
  }

  @Test
  void testGetSession() {
    assertEquals(
        123456789L, new SessionTimeoutException(123456789L).getSession(), "unexpected session");
  }
}

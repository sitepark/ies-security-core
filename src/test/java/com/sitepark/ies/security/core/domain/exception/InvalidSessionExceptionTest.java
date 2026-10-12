package com.sitepark.ies.security.core.domain.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;

class InvalidSessionExceptionTest {

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testMessageWithoutSessionId() {
    InvalidSessionException e = new InvalidSessionException("secret-session-id");
    assertEquals("Invalid session", e.getMessage(), "unexpected message");
    assertFalse(
        e.getMessage().contains("secret-session-id"), "message must not contain the session id");
  }

  @Test
  void testGetSession() {
    assertEquals(
        "secret-session-id",
        new InvalidSessionException("secret-session-id").getSession(),
        "unexpected session");
  }

  @Test
  void testCause() {
    Throwable cause = new IllegalStateException("cause");
    assertSame(cause, new InvalidSessionException("id", cause).getCause(), "unexpected cause");
  }
}

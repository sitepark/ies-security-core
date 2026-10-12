package com.sitepark.ies.security.core.domain.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;

class WebAuthnChallengeExpiredExceptionTest {

  @Test
  void testMessage() {
    assertEquals(
        "msg", new WebAuthnChallengeExpiredException("msg").getMessage(), "unexpected message");
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testMessageAndCause() {
    Throwable cause = new IllegalStateException("cause");
    WebAuthnChallengeExpiredException e = new WebAuthnChallengeExpiredException("msg", cause);
    assertEquals("msg", e.getMessage(), "unexpected message");
    assertSame(cause, e.getCause(), "unexpected cause");
  }

  @Test
  void testIsWebAuthnException() {
    assertInstanceOf(
        WebAuthnException.class,
        new WebAuthnChallengeExpiredException("msg"),
        "should be a WebAuthnException");
  }
}

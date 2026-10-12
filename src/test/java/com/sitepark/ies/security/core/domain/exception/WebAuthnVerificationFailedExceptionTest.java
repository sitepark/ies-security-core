package com.sitepark.ies.security.core.domain.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;

class WebAuthnVerificationFailedExceptionTest {

  @Test
  void testMessage() {
    assertEquals(
        "msg", new WebAuthnVerificationFailedException("msg").getMessage(), "unexpected message");
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void testMessageAndCause() {
    Throwable cause = new IllegalStateException("cause");
    WebAuthnVerificationFailedException e = new WebAuthnVerificationFailedException("msg", cause);
    assertEquals("msg", e.getMessage(), "unexpected message");
    assertSame(cause, e.getCause(), "unexpected cause");
  }

  @Test
  void testIsWebAuthnException() {
    assertInstanceOf(
        WebAuthnException.class,
        new WebAuthnVerificationFailedException("msg"),
        "should be a WebAuthnException");
  }
}

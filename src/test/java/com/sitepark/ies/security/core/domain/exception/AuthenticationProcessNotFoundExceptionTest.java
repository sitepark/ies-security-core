package com.sitepark.ies.security.core.domain.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sitepark.ies.sharedkernel.domain.DomainException;
import org.junit.jupiter.api.Test;

class AuthenticationProcessNotFoundExceptionTest {

  @Test
  void testMessage() {
    assertEquals(
        "Authentication process not found or expired",
        new AuthenticationProcessNotFoundException().getMessage(),
        "unexpected message");
  }

  @Test
  void testIsThrowableAsDomainException() {
    assertThrows(
        DomainException.class,
        () -> {
          throw new AuthenticationProcessNotFoundException();
        },
        "should be a DomainException");
  }
}

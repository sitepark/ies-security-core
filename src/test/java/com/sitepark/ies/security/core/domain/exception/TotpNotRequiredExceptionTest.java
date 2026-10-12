package com.sitepark.ies.security.core.domain.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sitepark.ies.sharedkernel.domain.DomainException;
import org.junit.jupiter.api.Test;

class TotpNotRequiredExceptionTest {

  @Test
  void testMessage() {
    assertEquals(
        "TOTP code validation is not required for this authentication process",
        new TotpNotRequiredException().getMessage(),
        "unexpected message");
  }

  @Test
  void testIsThrowableAsDomainException() {
    assertThrows(
        DomainException.class,
        () -> {
          throw new TotpNotRequiredException();
        },
        "should be a DomainException");
  }
}

package com.sitepark.ies.security.core.usecase.authentication;

import static org.junit.jupiter.api.Assertions.*;

import com.jparams.verifier.tostring.ToStringVerifier;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

class AuthenticationResultTest {
  @Test
  void testEquals() {
    EqualsVerifier.forClass(AuthenticationResult.class).verify();
  }

  @Test
  void testToString() {
    ToStringVerifier.forClass(AuthenticationResult.class).verify();
  }
}

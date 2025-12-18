package com.sitepark.ies.security.core.usecase.password;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class PasswordRecoverPayloadTest {

  @Test
  void testUsernameIsStored() {

    PasswordRecoverPayload payload = new PasswordRecoverPayload("testuser");

    assertEquals("testuser", payload.username(), "Username should match the provided value");
  }

  @Test
  void testDifferentUsername() {

    PasswordRecoverPayload payload = new PasswordRecoverPayload("anotheruser");

    assertEquals("anotheruser", payload.username(), "Username should match the provided value");
  }
}

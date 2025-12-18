package com.sitepark.ies.security.core.usecase.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class CreatePrivateTokenRequestTest {

  @Test
  void testValidRequestWithoutExpiration() {

    CreatePrivateTokenRequest request = new CreatePrivateTokenRequest("Test Token", null);

    assertEquals("Test Token", request.name(), "Name should match the provided value");
  }

  @Test
  void testExpirationIsNull() {

    CreatePrivateTokenRequest request = new CreatePrivateTokenRequest("Test Token", null);

    assertNull(request.expiresAt(), "ExpiresAt should be null when not provided");
  }

  @Test
  void testValidRequestWithExpiration() {

    Instant expiresAt = Instant.parse("2025-12-31T23:59:59Z");
    CreatePrivateTokenRequest request = new CreatePrivateTokenRequest("Test Token", expiresAt);

    assertEquals("Test Token", request.name(), "Name should match the provided value");
  }

  @Test
  void testExpirationIsSet() {

    Instant expiresAt = Instant.parse("2025-12-31T23:59:59Z");
    CreatePrivateTokenRequest request = new CreatePrivateTokenRequest("Test Token", expiresAt);

    assertEquals(expiresAt, request.expiresAt(), "ExpiresAt should match the provided value");
  }

  @Test
  void testNullNameThrowsException() {

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new CreatePrivateTokenRequest(null, null);
        },
        "Should throw IllegalArgumentException when name is null");
  }

  @Test
  void testBlankNameThrowsException() {

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new CreatePrivateTokenRequest("   ", null);
        },
        "Should throw IllegalArgumentException when name is blank");
  }

  @Test
  void testEmptyNameThrowsException() {

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new CreatePrivateTokenRequest("", null);
        },
        "Should throw IllegalArgumentException when name is empty");
  }
}

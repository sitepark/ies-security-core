package com.sitepark.ies.security.core.usecase.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class CreateImpersonationTokenRequestTest {

  @Test
  void testValidRequestWithoutExpiration() {

    CreateImpersonationTokenRequest request =
        new CreateImpersonationTokenRequest("user123", "Test Token", null);

    assertEquals("user123", request.userId(), "UserId should match the provided value");
  }

  @Test
  void testNameIsStored() {

    CreateImpersonationTokenRequest request =
        new CreateImpersonationTokenRequest("user123", "Test Token", null);

    assertEquals("Test Token", request.name(), "Name should match the provided value");
  }

  @Test
  void testExpirationIsNull() {

    CreateImpersonationTokenRequest request =
        new CreateImpersonationTokenRequest("user123", "Test Token", null);

    assertNull(request.expiresAt(), "ExpiresAt should be null when not provided");
  }

  @Test
  void testValidRequestWithExpiration() {

    Instant expiresAt = Instant.parse("2025-12-31T23:59:59Z");
    CreateImpersonationTokenRequest request =
        new CreateImpersonationTokenRequest("user123", "Test Token", expiresAt);

    assertEquals("user123", request.userId(), "UserId should match the provided value");
  }

  @Test
  void testExpirationIsSet() {

    Instant expiresAt = Instant.parse("2025-12-31T23:59:59Z");
    CreateImpersonationTokenRequest request =
        new CreateImpersonationTokenRequest("user123", "Test Token", expiresAt);

    assertEquals(expiresAt, request.expiresAt(), "ExpiresAt should match the provided value");
  }

  @Test
  void testNullNameThrowsException() {

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new CreateImpersonationTokenRequest("user123", null, null);
        },
        "Should throw IllegalArgumentException when name is null");
  }

  @Test
  void testBlankNameThrowsException() {

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new CreateImpersonationTokenRequest("user123", "   ", null);
        },
        "Should throw IllegalArgumentException when name is blank");
  }

  @Test
  void testEmptyNameThrowsException() {

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new CreateImpersonationTokenRequest("user123", "", null);
        },
        "Should throw IllegalArgumentException when name is empty");
  }
}

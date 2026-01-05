package com.sitepark.ies.security.core.usecase.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import com.sitepark.ies.sharedkernel.security.Permission;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class CreateServiceTokenRequestTest {

  @Test
  void testValidRequestWithoutExpiration() {

    Permission permission1 = mock(Permission.class);
    Permission permission2 = mock(Permission.class);
    List<Permission> permissions = List.of(permission1, permission2);
    CreateServiceTokenRequest request =
        new CreateServiceTokenRequest("Test Token", permissions, null);

    assertEquals("Test Token", request.name(), "Name should match the provided value");
  }

  @Test
  void testExpirationIsNull() {

    Permission permission = mock(Permission.class);
    List<Permission> permissions = List.of(permission);
    CreateServiceTokenRequest request =
        new CreateServiceTokenRequest("Test Token", permissions, null);

    assertNull(request.expiresAt(), "ExpiresAt should be null when not provided");
  }

  @Test
  void testValidRequestWithExpiration() {

    Permission permission = mock(Permission.class);
    List<Permission> permissions = List.of(permission);
    Instant expiresAt = Instant.parse("2025-12-31T23:59:59Z");
    CreateServiceTokenRequest request =
        new CreateServiceTokenRequest("Test Token", permissions, expiresAt);

    assertEquals("Test Token", request.name(), "Name should match the provided value");
  }

  @Test
  void testExpirationIsSet() {

    Permission permission = mock(Permission.class);
    List<Permission> permissions = List.of(permission);
    Instant expiresAt = Instant.parse("2025-12-31T23:59:59Z");
    CreateServiceTokenRequest request =
        new CreateServiceTokenRequest("Test Token", permissions, expiresAt);

    assertEquals(expiresAt, request.expiresAt(), "ExpiresAt should match the provided value");
  }

  @Test
  void testPermissionsAreStored() {

    Permission permission1 = mock(Permission.class);
    Permission permission2 = mock(Permission.class);
    List<Permission> permissions = List.of(permission1, permission2);
    CreateServiceTokenRequest request =
        new CreateServiceTokenRequest("Test Token", permissions, null);

    assertEquals(permissions, request.permissions(), "Permissions should match the provided list");
  }

  @Test
  void testPermissionsAreImmutable() {

    Permission permission = mock(Permission.class);
    List<Permission> permissions = List.of(permission);
    CreateServiceTokenRequest request =
        new CreateServiceTokenRequest("Test Token", permissions, null);

    Permission anotherPermission = mock(Permission.class);
    assertThrows(
        UnsupportedOperationException.class,
        () -> {
          request.permissions().add(anotherPermission);
        },
        "Permissions list should be immutable");
  }

  @Test
  void testEmptyPermissionsList() {

    CreateServiceTokenRequest request =
        new CreateServiceTokenRequest("Test Token", List.of(), null);

    assertEquals(List.of(), request.permissions(), "Empty permissions list should be allowed");
  }

  @Test
  void testNullNameThrowsException() {

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new CreateServiceTokenRequest(null, List.of(), null);
        },
        "Should throw IllegalArgumentException when name is null");
  }

  @Test
  void testBlankNameThrowsException() {

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new CreateServiceTokenRequest("   ", List.of(), null);
        },
        "Should throw IllegalArgumentException when name is blank");
  }

  @Test
  void testEmptyNameThrowsException() {

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new CreateServiceTokenRequest("", List.of(), null);
        },
        "Should throw IllegalArgumentException when name is empty");
  }
}

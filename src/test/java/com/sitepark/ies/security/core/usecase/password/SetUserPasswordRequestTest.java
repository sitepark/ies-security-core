package com.sitepark.ies.security.core.usecase.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

class SetUserPasswordRequestTest {

  @Test
  void testEquals() {
    EqualsVerifier.forClass(SetUserPasswordRequest.class).verify();
  }

  @Test
  void testUserIdIsStored() {

    SetUserPasswordRequest request =
        SetUserPasswordRequest.builder().userId("user123").newPassword("pass123").build();

    assertEquals("user123", request.userId(), "UserId should match the provided value");
  }

  @Test
  void testNewPasswordIsStored() {

    SetUserPasswordRequest request =
        SetUserPasswordRequest.builder().userId("user123").newPassword("pass123").build();

    assertEquals("pass123", request.newPassword(), "NewPassword should match the provided value");
  }

  @Test
  void testAuditParentIdIsNull() {

    SetUserPasswordRequest request =
        SetUserPasswordRequest.builder().userId("user123").newPassword("pass123").build();

    assertNull(request.auditParentId(), "AuditParentId should be null when not provided");
  }

  @Test
  void testAuditParentIdIsStored() {

    SetUserPasswordRequest request =
        SetUserPasswordRequest.builder()
            .userId("user123")
            .newPassword("pass123")
            .auditParentId("audit-456")
            .build();

    assertEquals(
        "audit-456", request.auditParentId(), "AuditParentId should match the provided value");
  }

  @Test
  void testNullUserIdThrowsException() {

    assertThrows(
        NullPointerException.class,
        () -> {
          SetUserPasswordRequest.builder().userId(null).newPassword("pass123").build();
        },
        "Should throw NullPointerException when userId is null");
  }

  @Test
  void testNullNewPasswordThrowsException() {

    assertThrows(
        NullPointerException.class,
        () -> {
          SetUserPasswordRequest.builder().userId("user123").newPassword(null).build();
        },
        "Should throw NullPointerException when newPassword is null");
  }

  @Test
  void testMissingUserIdThrowsException() {

    assertThrows(
        NullPointerException.class,
        () -> {
          SetUserPasswordRequest.builder().newPassword("pass123").build();
        },
        "Should throw NullPointerException when userId is not set");
  }

  @Test
  void testMissingNewPasswordThrowsException() {

    assertThrows(
        NullPointerException.class,
        () -> {
          SetUserPasswordRequest.builder().userId("user123").build();
        },
        "Should throw NullPointerException when newPassword is not set");
  }

  @Test
  void testToBuilder() {

    SetUserPasswordRequest original =
        SetUserPasswordRequest.builder()
            .userId("user123")
            .newPassword("pass123")
            .auditParentId("audit-456")
            .build();

    SetUserPasswordRequest copy = original.toBuilder().build();

    assertEquals(original, copy, "ToBuilder should create an equal copy");
  }

  @Test
  void testToBuilderModifiesUserId() {

    SetUserPasswordRequest original =
        SetUserPasswordRequest.builder().userId("user123").newPassword("pass123").build();

    SetUserPasswordRequest modified = original.toBuilder().userId("user456").build();

    assertEquals("user456", modified.userId(), "ToBuilder should allow modifying userId");
  }
}

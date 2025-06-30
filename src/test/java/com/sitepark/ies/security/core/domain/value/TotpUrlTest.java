package com.sitepark.ies.security.core.domain.value;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class TotpUrlTest {
  @Test
  void testNullIssuer() {
    assertThrows(
        NullPointerException.class,
        () -> {
          new TotpUrl(null, "test", "secrete");
        },
        "Issuer must not be null");
  }

  @Test
  void testBlankIssuer() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new TotpUrl(" ", "test", "secrete");
        },
        "Issuer must not be blank");
  }

  @Test
  void testNullAccount() {
    assertThrows(
        NullPointerException.class,
        () -> {
          new TotpUrl("test", null, "secrete");
        },
        "Account must not be null");
  }

  @Test
  void testBlankAccount() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new TotpUrl("test", " ", "secrete");
        },
        "Account must not be blank");
  }

  @Test
  void testNullSecret() {
    assertThrows(
        NullPointerException.class,
        () -> {
          new TotpUrl("test", "test", null);
        },
        "Secret must not be null");
  }

  @Test
  void testBlankSecret() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          new TotpUrl("test", "test", " ");
        },
        "Secret must not be blank");
  }

  @Test
  void testToString() {

    TotpUrl totpUrl = new TotpUrl("Test&Issuer", "Test?Account", "TestSecret");

    assertEquals(
        "otpauth://totp/Test%26Issuer:Test%3FAccount?secret=TestSecret&issuer=Test%26Issuer",
        totpUrl.toString(), "Unexpected TOTP URL format");
  }
}

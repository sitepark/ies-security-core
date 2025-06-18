package com.sitepark.ies.security.core.domain.entity;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class AuthenticatedUserTest {

  @Test
  @SuppressWarnings("PMD.JUnitTestContainsTooManyAsserts")
  void testId() {
    AuthenticatedUser user = AuthenticatedUser.builder().id("3").name("Test").login("test").build();
    assertEquals("3", user.getId(), "Wrong id");
  }

  @Test
  void testName() {
    AuthenticatedUser user = AuthenticatedUser.builder().id("3").name("Test").login("test").build();
    assertEquals("Test", user.getName(), "Wrong name");
  }

  @Test
  void testLogin() {
    AuthenticatedUser user = AuthenticatedUser.builder().id("3").name("Test").login("test").build();
    assertEquals("test", user.getLogin(), "Wrong login");
  }
}

package com.sitepark.ies.security.core.domain.entity;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class AuthenticatedUserTest {

  @Test
  @SuppressWarnings("PMD.JUnitTestContainsTooManyAsserts")
  void testId() {
    AuthenticatedUser user =
        AuthenticatedUser.builder().id("3").lastName("Test").username("test").build();
    assertEquals("3", user.getId(), "Wrong id");
  }

  @Test
  void testLastName() {
    AuthenticatedUser user =
        AuthenticatedUser.builder().id("3").lastName("Test").username("test").build();
    assertEquals("Test", user.getLastName(), "Wrong lastName");
  }

  @Test
  void testFirstName() {
    AuthenticatedUser user =
        AuthenticatedUser.builder()
            .id("3")
            .firstName("Abc")
            .lastName("Test")
            .username("test")
            .build();
    assertEquals("Abc", user.getFirstName(), "Wrong firstName");
  }

  @Test
  void testUsername() {
    AuthenticatedUser user =
        AuthenticatedUser.builder().id("3").lastName("Test").username("test").build();
    assertEquals("test", user.getUsername(), "Wrong username");
  }
}

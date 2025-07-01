package com.sitepark.ies.security.core.domain.entity;

import static org.junit.jupiter.api.Assertions.*;

import com.jparams.verifier.tostring.ToStringVerifier;
import com.sitepark.ies.sharedkernel.security.FullAccess;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.List;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class UserBasedAuthenticationTest {

  private User user;

  @BeforeEach
  void setUp() {
    this.user =
        User.builder().id("1").username("peterpan").firstName("Peter").lastName("Pan").build();
  }

  @Test
  void testEquals() {
    EqualsVerifier.forClass(UserBasedAuthentication.class).verify();
  }

  @Test
  void testToString() {
    ToStringVerifier.forClass(UserBasedAuthentication.class).verify();
  }

  @Test
  void testUser() {
    UserBasedAuthentication authentication =
        UserBasedAuthentication.builder().user(this.user).purpose("test").build();
    assertEquals(this.user, authentication.user(), "User should match the one set in builder");
  }

  @Test
  void testUserWithNull() {
    assertThrows(
        NullPointerException.class,
        () -> UserBasedAuthentication.builder().user(null),
        "User should not be null");
  }

  @Test
  void testPermissions() {
    UserBasedAuthentication authentication =
        UserBasedAuthentication.builder()
            .user(this.user)
            .permissions(List.of(new FullAccess()))
            .purpose("test")
            .build();
    assertEquals(
        List.of(new FullAccess()),
        authentication.permissions(),
        "Permissions should match the ones set in builder");
  }

  @Test
  void testPermissionsWithNull() {
    assertThrows(
        NullPointerException.class,
        () -> UserBasedAuthentication.builder().permissions(null),
        "Permissions should not be null");
  }

  @Test
  void testPermissionWithNul() {
    assertThrows(
        NullPointerException.class,
        () -> UserBasedAuthentication.builder().permission(null),
        "Permission should not be null");
  }

  @Test
  void testPurpose() {
    UserBasedAuthentication authentication =
        UserBasedAuthentication.builder().user(this.user).purpose("test").build();
    assertEquals("test", authentication.purpose(), "Purpose should match the one set in builder");
  }

  @Test
  void testName() {
    UserBasedAuthentication authentication =
        UserBasedAuthentication.builder().user(this.user).purpose("test").build();
    assertEquals("Peter Pan", authentication.name(), "Name should be derived from user");
  }
}

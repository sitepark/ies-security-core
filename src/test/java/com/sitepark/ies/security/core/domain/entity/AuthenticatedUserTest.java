package com.sitepark.ies.security.core.domain.entity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.jparams.verifier.tostring.ToStringVerifier;
import com.sitepark.ies.sharedkernel.security.AuthFactor;
import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.List;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuthenticatedUserTest {

  private AuthenticatedUser user;

  @BeforeEach
  void setUp() {
    this.user =
        AuthenticatedUser.builder()
            .id("1")
            .username("testUser")
            .firstName("Test")
            .lastName("User")
            .email("test@test.com")
            .authMethods(AuthMethod.PASSWORD)
            .authFactors(AuthFactor.TOTP)
            .build();
  }

  @Test
  void testEquals() {
    EqualsVerifier.forClass(AuthenticatedUser.class).verify();
  }

  @Test
  void testToString() {
    ToStringVerifier.forClass(AuthenticatedUser.class).verify();
  }

  @Test
  void testGetName() {
    assertEquals(
        "Test User",
        this.user.getName(),
        "getName should return 'Test User' for first and last name");
  }

  @Test
  void testGetId() {
    assertEquals("1", this.user.id(), "Unexpected id value");
  }

  @Test
  void testGetUsername() {
    assertEquals("testUser", this.user.username(), "Unexpected username value");
  }

  @Test
  void testGetFirstName() {
    assertEquals("Test", this.user.firstName(), "Unexpected firstName value");
  }

  @Test
  void testGetLastName() {
    assertEquals("User", this.user.lastName(), "Unexpected lastName value");
  }

  @Test
  void testGetEmail() {
    assertEquals("test@test.com", this.user.email(), "Unexpected email value");
  }

  @Test
  void testGetNameWithBlankFirstName() {
    AuthenticatedUser user =
        AuthenticatedUser.builder()
            .id("1")
            .username("testUser")
            .firstName(" ")
            .lastName("User")
            .email("test@test.com")
            .authMethods(AuthMethod.PASSWORD)
            .authFactors(AuthFactor.TOTP)
            .build();

    assertEquals("User", user.getName(), "getName should return 'User' when first name is blank");
  }

  @Test
  void testGetNameWithNullFirstName() {
    AuthenticatedUser user =
        AuthenticatedUser.builder()
            .id("1")
            .username("testUser")
            .lastName("User")
            .email("test@test.com")
            .authMethods(AuthMethod.PASSWORD)
            .authFactors(AuthFactor.TOTP)
            .build();
    assertEquals("User", user.getName(), "getName should return 'User' when first name is blank");
  }

  @Test
  void testWithNullLastName() {
    assertThrows(
        NullPointerException.class,
        () ->
            AuthenticatedUser.builder()
                .id("1")
                .username("testUser")
                .firstName("Test")
                .email("test@test.com")
                .authMethods(AuthMethod.PASSWORD)
                .authFactors(AuthFactor.TOTP)
                .build());
  }

  @Test
  void testWithBlankLastName() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            AuthenticatedUser.builder()
                .id("1")
                .username("testUser")
                .firstName("Test")
                .lastName(" ")
                .email("test@test.com")
                .authMethods(AuthMethod.PASSWORD)
                .authFactors(AuthFactor.TOTP)
                .build());
  }

  @Test
  void testAuthMethodCollection() {
    AuthenticatedUser.builder()
        .id("1")
        .username("testUser")
        .firstName("Test")
        .lastName("User")
        .email("test@test.com")
        .authMethods(List.of(AuthMethod.PASSWORD))
        .build();

    assertEquals(
        List.of(AuthMethod.PASSWORD),
        this.user.authMethods(),
        "authMethods should return the correct AuthMethod");
  }

  @Test
  void testAuthMethodCollectionWithNull() {
    assertThrows(
        NullPointerException.class,
        () -> AuthenticatedUser.builder().authMethods(List.of((AuthMethod) null)));
  }

  @Test
  void testNullAuthMethod() {
    assertThrows(
        NullPointerException.class,
        () -> AuthenticatedUser.builder().authMethods((AuthMethod) null));
  }

  @Test
  void testGetAuthMethods() {
    assertThrows(
        UnsupportedOperationException.class,
        () -> this.user.authMethods().add(null),
        "authFactors should return a copy of the original");
  }

  @Test
  void testAuthFactorCollection() {
    AuthenticatedUser.builder()
        .id("1")
        .username("testUser")
        .firstName("Test")
        .lastName("User")
        .email("test@test.com")
        .authFactors(List.of(AuthFactor.TOTP))
        .build();

    assertEquals(
        List.of(AuthMethod.PASSWORD),
        this.user.authMethods(),
        "authMethods should return the correct AuthMethod");
  }

  @Test
  void testAuthFactorCollectionWithNull() {
    assertThrows(
        NullPointerException.class,
        () -> AuthenticatedUser.builder().authFactors(List.of((AuthFactor) null)));
  }

  @Test
  void testNullAuthFactor() {
    assertThrows(
        NullPointerException.class,
        () -> AuthenticatedUser.builder().authFactors((AuthFactor) null));
  }

  @Test
  void testGetAuthFactor() {
    assertThrows(
        UnsupportedOperationException.class,
        () -> this.user.authFactors().add(null),
        "authFactors should return a copy of the original");
  }

  @Test
  void testToBuilder() {
    AuthenticatedUser user =
        AuthenticatedUser.builder()
            .id("1")
            .username("testUser")
            .lastName("User")
            .email("test@test.com")
            .authMethods(AuthMethod.PASSWORD)
            .authFactors(AuthFactor.TOTP)
            .build()
            .toBuilder()
            .email("test2@test.com")
            .build();

    AuthenticatedUser expectedUser =
        AuthenticatedUser.builder()
            .id("1")
            .username("testUser")
            .lastName("User")
            .email("test2@test.com")
            .authMethods(AuthMethod.PASSWORD)
            .authFactors(AuthFactor.TOTP)
            .build();

    assertEquals(expectedUser, user, "toBuilder should return the same object");
  }

  @Test
  void testFromUser() {
    User user =
        User.builder()
            .id("1")
            .username("testUser")
            .lastName("User")
            .email("test@test.com")
            .authMethods(AuthMethod.PASSWORD)
            .authFactors(AuthFactor.TOTP)
            .passwordHash("hash")
            .build();

    AuthenticatedUser authenticatedUser = AuthenticatedUser.fromUser(user);

    AuthenticatedUser expectedUser =
        AuthenticatedUser.builder()
            .id("1")
            .username("testUser")
            .lastName("User")
            .email("test@test.com")
            .authMethods(AuthMethod.PASSWORD)
            .authFactors(AuthFactor.TOTP)
            .build();

    assertEquals(expectedUser, authenticatedUser, "fromUser should return the same object");
  }
}

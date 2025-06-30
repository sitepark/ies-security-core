package com.sitepark.ies.security.core.domain.entity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

import com.jparams.verifier.tostring.ToStringVerifier;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

class SessionTest {

  private final Clock fixedClock =
      Clock.fixed(Instant.parse("2025-06-30T10:00:00Z"), ZoneId.of("UTC"));

  @Test
  void testEquals() {
    EqualsVerifier.forClass(Session.class).verify();
  }

  @Test
  void testToString() {
    ToStringVerifier.forClass(Session.class).verify();
  }

  @Test
  void testId() {
    Session session = Session.builder().id("1").build();
    assertEquals("1", session.id(), "Session id should be '1'");
  }

  @Test
  void testIdWithNull() {
    assertThrows(
        NullPointerException.class,
        () -> Session.builder().id(null).build(),
        "Session id should not be null");
  }

  @Test
  void testIdWithBlankString() {
    assertThrows(
        IllegalArgumentException.class,
        () -> Session.builder().id(" ").build(),
        "Session id should not be blank");
  }

  @Test
  void testCreatedAt() {
    Instant now = Instant.now(this.fixedClock);
    Session session = Session.builder().createdAt(now).build();
    assertEquals(now, session.createdAt(), "Session createdAt should match the provided Instant");
  }

  @Test
  void testCreatedAtWithNull() {
    assertThrows(
        NullPointerException.class,
        () -> Session.builder().createdAt(null).build(),
        "Session createdAt should not be null");
  }

  @Test
  void testAuthentication() {
    UserBasedAuthentication authentication = mock();
    Session session = Session.builder().authentication(authentication).build();
    assertEquals(
        authentication,
        session.authentication(),
        "Session authentication should match the provided UserBasedAuthentication");
  }

  @Test
  void testAuthenticationWithNull() {
    assertThrows(
        NullPointerException.class,
        () -> Session.builder().authentication(null).build(),
        "Session authentication should not be null");
  }

  @Test
  void testToBuilder() {
    UserBasedAuthentication authentication = mock();
    Session session =
        Session.builder()
            .id("1")
            .createdAt(Instant.now(this.fixedClock))
            .authentication(authentication)
            .build()
            .toBuilder()
            .id("2")
            .build();

    Session expected =
        Session.builder()
            .id("2")
            .createdAt(Instant.now(this.fixedClock))
            .authentication(authentication)
            .build();

    assertEquals(expected, session, "Session should be equal after toBuilder and id change");
  }
}

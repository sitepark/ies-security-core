package com.sitepark.ies.security.core.domain.entity;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sitepark.ies.security.core.domain.value.TokenType;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

@SuppressWarnings({"PMD.TooManyMethods", "PMD.AvoidDuplicateLiterals"})
@SuppressFBWarnings({
  "PI_DO_NOT_REUSE_PUBLIC_IDENTIFIERS_CLASS_NAMES",
  "NP_NULL_PARAM_DEREF_NONVIRTUAL",
  "NP_NULL_PARAM_DEREF_ALL_TARGETS_DANGEROUS"
})
class AccessTokenTest {

  private static final ZoneId ZONE_ID = ZoneId.of("Europe/Berlin");

  private static final String TOKEN_NAME = "Test Token";

  @Test
  void testEquals() {
    EqualsVerifier.forClass(AccessToken.class).verify();
  }

  @Test
  void testSetUser() throws JsonProcessingException {
    AccessToken accessToken =
        AccessToken.builder()
            .userId("345")
            .name(TOKEN_NAME)
            .tokenType(TokenType.IMPERSONATION)
            .build();
    assertEquals("345", accessToken.userId(), "wrong user");
  }

  @Test
  void testSetUserWithNull() throws JsonProcessingException {
    assertThrows(
        NullPointerException.class,
        () -> {
          AccessToken.builder().userId(null);
        });
  }

  @Test
  void testSetName() throws JsonProcessingException {
    AccessToken accessToken =
        AccessToken.builder()
            .userId("345")
            .name(TOKEN_NAME)
            .tokenType(TokenType.IMPERSONATION)
            .build();
    assertEquals(TOKEN_NAME, accessToken.name(), "wrong name");
  }

  @Test
  void testSetNullName() throws JsonProcessingException {
    assertThrows(
        NullPointerException.class,
        () -> {
          AccessToken.builder().name(null);
        });
  }

  @Test
  void testSetBlankName() throws JsonProcessingException {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          AccessToken.builder().name(" ");
        });
  }

  @Test
  void testBuildUserNotSet() throws JsonProcessingException {
    assertThrows(
        NullPointerException.class,
        () -> {
          AccessToken.builder().name(TOKEN_NAME).build();
        });
  }

  @Test
  void testBuildNameNotSet() throws JsonProcessingException {
    assertThrows(
        NullPointerException.class,
        () -> {
          AccessToken.builder().userId("123").build();
        });
  }

  @Test
  void testSetId() throws JsonProcessingException {
    AccessToken accessToken = this.createBuilderWithRequiredValues().id("123").build();
    assertEquals("123", accessToken.id(), "wrong id");
  }

  @Test
  void testGetEmptyId() throws JsonProcessingException {
    AccessToken accessToken = this.createBuilderWithRequiredValues().build();
    assertNull(accessToken.id(), "id should be null");
  }

  @Test
  void testSetIdWithNull() throws JsonProcessingException {
    assertThrows(
        NullPointerException.class,
        () -> {
          AccessToken.builder().id(null);
        });
  }

  @Test
  void testSetCreatedAt() throws JsonProcessingException {

    Instant createdAt = LocalDate.of(2023, 8, 21).atStartOfDay().atZone(ZONE_ID).toInstant();

    AccessToken accessToken = this.createBuilderWithRequiredValues().createdAt(createdAt).build();

    assertEquals(createdAt, accessToken.createdAt(), "unexpected createAt");
  }

  @Test
  void testSetExpiresAt() throws JsonProcessingException {

    Instant expiresAt = LocalDate.of(2023, 8, 21).atStartOfDay().atZone(ZONE_ID).toInstant();

    AccessToken accessToken = this.createBuilderWithRequiredValues().expiresAt(expiresAt).build();

    assertEquals(expiresAt, accessToken.expiresAt(), "unexpected expiresAt");
  }

  @Test
  void testSetLastUsed() throws JsonProcessingException {

    Instant lastUsed = LocalDate.of(2023, 8, 21).atStartOfDay().atZone(ZONE_ID).toInstant();

    AccessToken accessToken = this.createBuilderWithRequiredValues().lastUsedAt(lastUsed).build();

    assertEquals(lastUsed, accessToken.lastUsedAt(), "unexpected lastUsed");
  }

  @Test
  void testSetActiveTrue() throws JsonProcessingException {
    AccessToken accessToken = this.createBuilderWithRequiredValues().active(true).build();
    assertTrue(accessToken.active(), "unexpected active");
  }

  @Test
  void testSetActiveFalse() throws JsonProcessingException {
    AccessToken accessToken = this.createBuilderWithRequiredValues().active(false).build();
    assertFalse(accessToken.active(), "unexpected active");
  }

  @Test
  void testSetRevokedTrue() throws JsonProcessingException {
    AccessToken accessToken = this.createBuilderWithRequiredValues().revoked(true).build();
    assertTrue(accessToken.revoked(), "unexpected revoked");
  }

  @Test
  void testSetRevokedFalse() throws JsonProcessingException {
    AccessToken accessToken = this.createBuilderWithRequiredValues().revoked(false).build();
    assertFalse(accessToken.revoked(), "unexpected revoked");
  }

  @Test
  void testSerialize() throws JsonProcessingException {

    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModule(new Jdk8Module());
    mapper.registerModule(new JavaTimeModule());
    mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
    mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    Instant createdAt = LocalDate.of(2023, 8, 21).atStartOfDay().atZone(ZONE_ID).toInstant();
    Instant expiredAt = LocalDate.of(2023, 12, 12).atStartOfDay().atZone(ZONE_ID).toInstant();
    Instant lastUsedAt = LocalDate.of(2023, 8, 25).atStartOfDay().atZone(ZONE_ID).toInstant();

    AccessToken accessToken =
        AccessToken.builder()
            .id("123")
            .userId("345")
            .name(TOKEN_NAME)
            .createdAt(createdAt)
            .expiresAt(expiredAt)
            .lastUsedAt(lastUsedAt)
            .tokenType(TokenType.IMPERSONATION)
            .build();

    String json = mapper.writeValueAsString(accessToken);

    String expected =
        """
        {\
        "id":"123",\
        "userId":"345",\
        "name":"Test Token",\
        "createdAt":"2023-08-20T22:00:00Z",\
        "expiresAt":"2023-12-11T23:00:00Z",\
        "lastUsed":"2023-08-24T22:00:00Z",\
        "tokenType":"IMPERSONATION",\
        "active":true,\
        "revoked":false\
        }\
        """;

    assertEquals(expected, json, "unexpected json");
  }

  @Test
  void testDeserialize() throws JsonProcessingException {

    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModule(new Jdk8Module());
    mapper.registerModule(new JavaTimeModule());
    mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    String json =
        """
        {\
        "id":123,\
        "userId":345,\
        "name":"Test Token",\
        "createdAt":"2023-08-21T00:00:00+02:00",\
        "expiresAt":"2023-12-12T00:00:00+01:00",\
        "lastUsed":"2023-08-25T00:00:00+02:00",\
        "tokenType":"IMPERSONATION",\
        "active":true,\
        "revoked":false\
        }\
        """;

    AccessToken accessToken = mapper.readValue(json, AccessToken.class);

    Instant createdAt = LocalDate.of(2023, 8, 21).atStartOfDay().atZone(ZONE_ID).toInstant();
    Instant expiredAt = LocalDate.of(2023, 12, 12).atStartOfDay().atZone(ZONE_ID).toInstant();
    Instant lastUsedAt = LocalDate.of(2023, 8, 25).atStartOfDay().atZone(ZONE_ID).toInstant();

    AccessToken expected =
        AccessToken.builder()
            .id("123")
            .userId("345")
            .name(TOKEN_NAME)
            .createdAt(createdAt)
            .expiresAt(expiredAt)
            .lastUsedAt(lastUsedAt)
            .tokenType(TokenType.IMPERSONATION)
            .build();

    assertEquals(expected, accessToken, "unexpected accessToken");
  }

  private AccessToken.Builder createBuilderWithRequiredValues() {
    return AccessToken.builder().userId("345").name(TOKEN_NAME).tokenType(TokenType.IMPERSONATION);
  }
}

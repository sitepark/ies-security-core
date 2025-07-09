package com.sitepark.ies.security.core.domain.entity;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.List;
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
    AccessToken accessToken = AccessToken.builder().user("345").name(TOKEN_NAME).build();
    assertEquals("345", accessToken.user(), "wrong user");
  }

  @Test
  void testSetUserWithNull() throws JsonProcessingException {
    assertThrows(
        NullPointerException.class,
        () -> {
          AccessToken.builder().user(null);
        });
  }

  @Test
  void testSetUserWithZero() throws JsonProcessingException {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          AccessToken.builder().user("0");
        });
  }

  @Test
  void testSetUserWithInvalidValue() throws JsonProcessingException {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          AccessToken.builder().user("1x");
        });
  }

  @Test
  void testSetName() throws JsonProcessingException {
    AccessToken accessToken = AccessToken.builder().user("345").name(TOKEN_NAME).build();
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
          AccessToken.builder().user("123").build();
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
  void testSetIdWithZero() throws JsonProcessingException {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          AccessToken.builder().id("0");
        });
  }

  @Test
  void testSetIdWithInvalidValue() throws JsonProcessingException {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          AccessToken.builder().id("1x");
        });
  }

  @Test
  void testSetToken() throws JsonProcessingException {
    AccessToken accessToken = this.createBuilderWithRequiredValues().token("abc").build();
    assertEquals("abc", accessToken.token(), "wrong token");
  }

  @Test
  void testSetNullToken() throws JsonProcessingException {
    assertThrows(
        NullPointerException.class,
        () -> {
          AccessToken.builder().token(null);
        });
  }

  @Test
  void testSetBlankToken() throws JsonProcessingException {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          AccessToken.builder().token(" ");
        });
  }

  @Test
  void testSetCreatedAt() throws JsonProcessingException {

    Instant createdAt = LocalDate.of(2023, 8, 21).atStartOfDay().atZone(ZONE_ID).toInstant();

    AccessToken accessToken = this.createBuilderWithRequiredValues().createdAt(createdAt).build();

    assertEquals(createdAt, accessToken.createdAt(), "unexpected createAt");
  }

  @Test
  void testSetNullCreatedAt() throws JsonProcessingException {
    assertThrows(
        NullPointerException.class,
        () -> {
          AccessToken.builder().createdAt(null);
        });
  }

  @Test
  void testSetExpiresAt() throws JsonProcessingException {

    Instant expiresAt = LocalDate.of(2023, 8, 21).atStartOfDay().atZone(ZONE_ID).toInstant();

    AccessToken accessToken = this.createBuilderWithRequiredValues().expiresAt(expiresAt).build();

    assertEquals(expiresAt, accessToken.expiresAt(), "unexpected expiresAt");
  }

  @Test
  void testSetNullExpiresAt() throws JsonProcessingException {
    assertThrows(
        NullPointerException.class,
        () -> {
          AccessToken.builder().expiresAt(null);
        });
  }

  @Test
  void testSetLastUsed() throws JsonProcessingException {

    Instant lastUsed = LocalDate.of(2023, 8, 21).atStartOfDay().atZone(ZONE_ID).toInstant();

    AccessToken accessToken = this.createBuilderWithRequiredValues().lastUsed(lastUsed).build();

    assertEquals(lastUsed, accessToken.lastUsed(), "unexpected lastUsed");
  }

  @Test
  void testSetNullLastUsed() throws JsonProcessingException {
    assertThrows(
        NullPointerException.class,
        () -> {
          AccessToken.builder().lastUsed(null);
        });
  }

  @Test
  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  void testSetScopeListViaList() throws JsonProcessingException {
    AccessToken accessToken =
        this.createBuilderWithRequiredValues().scopeList(Arrays.asList("a", "b")).build();

    assertEquals(Arrays.asList("a", "b"), accessToken.scopeList(), "unexpected scopeList");
  }

  @Test
  void testSetNullScopeListViaList() throws JsonProcessingException {
    assertThrows(
        NullPointerException.class,
        () -> {
          AccessToken.builder().scopeList((List<String>) null);
        });
  }

  @Test
  void testSetNullScopeViaList() throws JsonProcessingException {
    assertThrows(
        NullPointerException.class,
        () -> {
          AccessToken.builder().scopeList(Arrays.asList("a", null));
        });
  }

  @Test
  void testSetBlankScopeListViaList() throws JsonProcessingException {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          AccessToken.builder().scopeList(Arrays.asList("a", " "));
        });
  }

  @Test
  void testOverwriteScopeListViaList() throws JsonProcessingException {
    AccessToken accessToken =
        this.createBuilderWithRequiredValues().scopeList(Arrays.asList("a", "b")).build();

    AccessToken overwritten = accessToken.toBuilder().scopeList(Arrays.asList("c", "d")).build();

    assertEquals(Arrays.asList("c", "d"), overwritten.scopeList(), "unexpected scopeList");
  }

  @Test
  void testSetScopeListViaVArgs() throws JsonProcessingException {
    AccessToken accessToken = this.createBuilderWithRequiredValues().scopeList("a", "b").build();

    assertEquals(Arrays.asList("a", "b"), accessToken.scopeList(), "unexpected scopeList");
  }

  @Test
  void testOverwriteScopeListViaVArgs() throws JsonProcessingException {
    AccessToken accessToken = this.createBuilderWithRequiredValues().scopeList("a", "b").build();
    AccessToken overwritten = accessToken.toBuilder().scopeList("c", "d").build();

    assertEquals(Arrays.asList("c", "d"), overwritten.scopeList(), "unexpected scopeList");
  }

  @Test
  void testSetNullScopeListViaVArgs() throws JsonProcessingException {
    assertThrows(
        NullPointerException.class,
        () -> {
          AccessToken.builder().scopeList((String[]) null);
        });
  }

  @Test
  void testSetNullScopeViaVArgs() throws JsonProcessingException {
    assertThrows(
        NullPointerException.class,
        () -> {
          AccessToken.builder().scopeList("a", null);
        });
  }

  @Test
  void testSetBlankScopeViaVArgs() throws JsonProcessingException {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          AccessToken.builder().scopeList("a", " ");
        });
  }

  @Test
  void testAddScope() throws JsonProcessingException {
    AccessToken accessToken = this.createBuilderWithRequiredValues().scopeList("a", "b").build();

    AccessToken addition = accessToken.toBuilder().scope("c").build();

    assertEquals(Arrays.asList("a", "b", "c"), addition.scopeList(), "unexpected scopes");
  }

  @Test
  void testAddNullScope() throws JsonProcessingException {
    assertThrows(
        NullPointerException.class,
        () -> {
          this.createBuilderWithRequiredValues().scope(null);
        });
  }

  @Test
  void testAddBlankScope() throws JsonProcessingException {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          AccessToken.builder().scope(" ");
        });
  }

  @Test
  void testSetImpersonationTrue() throws JsonProcessingException {
    AccessToken accessToken = this.createBuilderWithRequiredValues().impersonation(true).build();
    assertTrue(accessToken.impersonation(), "unexpected impersonation");
  }

  @Test
  void testSetImpersonationFalse() throws JsonProcessingException {
    AccessToken accessToken = this.createBuilderWithRequiredValues().impersonation(false).build();
    assertFalse(accessToken.impersonation(), "unexpected impersonation");
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
    Instant lastUpdate = LocalDate.of(2023, 8, 25).atStartOfDay().atZone(ZONE_ID).toInstant();

    AccessToken accessToken =
        AccessToken.builder()
            .id("123")
            .user("345")
            .name(TOKEN_NAME)
            .createdAt(createdAt)
            .expiresAt(expiredAt)
            .lastUsed(lastUpdate)
            .impersonation(true)
            .build();

    String json = mapper.writeValueAsString(accessToken);

    String expected =
        """
        {\
        "id":"123",\
        "user":"345",\
        "name":"Test Token",\
        "createdAt":"2023-08-20T22:00:00Z",\
        "expiresAt":"2023-12-11T23:00:00Z",\
        "lastUsed":"2023-08-24T22:00:00Z",\
        "impersonation":true,\
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
        "user":345,\
        "name":"Test Token",\
        "createdAt":"2023-08-21T00:00:00+02:00",\
        "expiresAt":"2023-12-12T00:00:00+01:00",\
        "lastUsed":"2023-08-25T00:00:00+02:00",\
        "impersonation":true,\
        "active":true,\
        "revoked":false\
        }\
        """;

    AccessToken accessToken = mapper.readValue(json, AccessToken.class);

    Instant createdAt = LocalDate.of(2023, 8, 21).atStartOfDay().atZone(ZONE_ID).toInstant();
    Instant expiredAt = LocalDate.of(2023, 12, 12).atStartOfDay().atZone(ZONE_ID).toInstant();
    Instant lastUpdate = LocalDate.of(2023, 8, 25).atStartOfDay().atZone(ZONE_ID).toInstant();

    AccessToken expected =
        AccessToken.builder()
            .id("123")
            .user("345")
            .name(TOKEN_NAME)
            .createdAt(createdAt)
            .expiresAt(expiredAt)
            .lastUsed(lastUpdate)
            .impersonation(true)
            .build();

    assertEquals(expected, accessToken, "unexpected accessToken");
  }

  private AccessToken.Builder createBuilderWithRequiredValues() {
    return AccessToken.builder().user("345").name(TOKEN_NAME);
  }
}

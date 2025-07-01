package com.sitepark.ies.security.core.usecase.authentication;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jparams.verifier.tostring.ToStringVerifier;
import com.sitepark.ies.security.core.domain.value.AuthenticationRequirement;
import com.sitepark.ies.security.core.domain.value.AuthenticationStatus;
import com.sitepark.ies.sharedkernel.security.User;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

class AuthenticationResultTest {
  @Test
  void testEquals() {
    EqualsVerifier.forClass(AuthenticationResult.class).verify();
  }

  @Test
  void testToString() {
    ToStringVerifier.forClass(AuthenticationResult.class).verify();
  }

  @Test
  void testFailure() {
    AuthenticationResult result = AuthenticationResult.failure();
    assertEquals(AuthenticationStatus.FAILURE, result.status(), "Unexpected status");
  }

  @Test
  void testSuccess() {
    User user = User.builder().id("1").username("test").lastName("test").build();
    AuthenticationResult result = AuthenticationResult.success(user);
    assertEquals(AuthenticationStatus.SUCCESS, result.status(), "Unexpected status");
  }

  @Test
  void testPartial() {
    AuthenticationResult result =
        AuthenticationResult.partial(
            "123", new AuthenticationRequirement[] {AuthenticationRequirement.TOTP_CODE_REQUIRED});
    assertEquals(AuthenticationStatus.PARTIAL, result.status(), "Unexpected status");
  }

  @Test
  void testSerializeFailure() throws JsonProcessingException {
    ObjectMapper mapper = new ObjectMapper();
    mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
    AuthenticationResult result = AuthenticationResult.failure();
    String json = mapper.writeValueAsString(result);
    String expected =
        """
        {"status":"FAILURE"}\
        """;

    assertEquals(expected, json, "JSON serialization should match expected format");
  }

  @Test
  void testSerializeSuccess() throws JsonProcessingException {
    ObjectMapper mapper = new ObjectMapper();
    mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
    User user = User.builder().id("1").username("test").lastName("test").build();
    AuthenticationResult result = AuthenticationResult.success(user);
    String json = mapper.writeValueAsString(result);
    String expected =
        """
        {"status":"SUCCESS","user":{"id":"1","username":"test","lastName":"test"}}\
        """;

    assertEquals(expected, json, "JSON serialization should match expected format");
  }

  @Test
  void testSerializePartial() throws JsonProcessingException {
    ObjectMapper mapper = new ObjectMapper();
    mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
    AuthenticationResult result =
        AuthenticationResult.partial(
            "123", new AuthenticationRequirement[] {AuthenticationRequirement.TOTP_CODE_REQUIRED});
    String json = mapper.writeValueAsString(result);
    String expected =
        """
        {"status":"PARTIAL","authProcessId":"123","requirements":["TOTP_CODE_REQUIRED"]}\
        """;

    assertEquals(expected, json, "JSON serialization should match expected format");
  }
}

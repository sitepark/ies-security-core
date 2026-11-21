package com.sitepark.ies.security.core.domain.value;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.jparams.verifier.tostring.ToStringVerifier;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.List;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.json.JsonMapper;

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
    AuthenticationResult result = AuthenticationResult.success(user, "purpose");
    assertEquals(AuthenticationStatus.SUCCESS, result.status(), "Unexpected status");
  }

  @Test
  void testPartial() {
    AuthenticationResult result =
        AuthenticationResult.partial("123", List.of(AuthenticationRequirement.TOTP_CODE_REQUIRED));
    assertEquals(AuthenticationStatus.PARTIAL, result.status(), "Unexpected status");
  }

  @Test
  void testSerializeFailure() {
    JsonMapper mapper =
        JsonMapper.builder()
            .disable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
            .changeDefaultPropertyInclusion(
                inclusion -> inclusion.withValueInclusion(JsonInclude.Include.NON_EMPTY))
            .build();
    AuthenticationResult result = AuthenticationResult.failure();
    String json = mapper.writeValueAsString(result);
    String expected =
        """
        {"status":"FAILURE"}\
        """;

    assertEquals(expected, json, "JSON serialization should match expected format");
  }

  @Test
  void testSerializeSuccess() {
    JsonMapper mapper =
        JsonMapper.builder()
            .disable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
            .changeDefaultPropertyInclusion(
                inclusion -> inclusion.withValueInclusion(JsonInclude.Include.NON_EMPTY))
            .build();
    User user = User.builder().id("1").username("test").lastName("test").build();
    AuthenticationResult result = AuthenticationResult.success(user, "purpose");
    String json = mapper.writeValueAsString(result);
    String expected =
        """
        {"status":"SUCCESS","user":{"id":"1","username":"test","lastName":"test","identity":{"type":"internal"}},"purpose":"purpose"}\
        """;

    assertEquals(expected, json, "JSON serialization should match expected format");
  }

  @Test
  void testSerializePartial() {
    JsonMapper mapper =
        JsonMapper.builder()
            .disable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
            .changeDefaultPropertyInclusion(
                inclusion -> inclusion.withValueInclusion(JsonInclude.Include.NON_EMPTY))
            .build();
    AuthenticationResult result =
        AuthenticationResult.partial("123", List.of(AuthenticationRequirement.TOTP_CODE_REQUIRED));
    String json = mapper.writeValueAsString(result);
    String expected =
        """
        {"status":"PARTIAL","authProcessId":"123","requirements":["TOTP_CODE_REQUIRED"]}\
        """;

    assertEquals(expected, json, "JSON serialization should match expected format");
  }
}

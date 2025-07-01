package com.sitepark.ies.security.core.usecase.authentication;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sitepark.ies.sharedkernel.security.AuthMethod;
import java.util.List;
import org.junit.jupiter.api.Test;

class AuthenticationInfoTest {

  @Test
  void testSerialize() throws JsonProcessingException {
    ObjectMapper mapper = new ObjectMapper();
    AuthenticationInfo info = new AuthenticationInfo(List.of(AuthMethod.PASSWORD));

    String json = mapper.writeValueAsString(info);
    String expected =
        """
        {"authMethods":["PASSWORD"]}\
        """;

    assertEquals(expected, json, "JSON serialization should match expected format");
  }
}

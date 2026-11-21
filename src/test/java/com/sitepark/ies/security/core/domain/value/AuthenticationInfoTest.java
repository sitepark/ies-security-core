package com.sitepark.ies.security.core.domain.value;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.sitepark.ies.sharedkernel.security.AuthMethod;
import java.util.List;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.json.JsonMapper;

class AuthenticationInfoTest {

  @Test
  void testSerialize() {
    JsonMapper mapper =
        JsonMapper.builder().disable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY).build();
    AuthenticationInfo info = new AuthenticationInfo(List.of(AuthMethod.PASSWORD));

    String json = mapper.writeValueAsString(info);
    String expected =
        """
        {"authMethods":["PASSWORD"]}\
        """;

    assertEquals(expected, json, "JSON serialization should match expected format");
  }
}

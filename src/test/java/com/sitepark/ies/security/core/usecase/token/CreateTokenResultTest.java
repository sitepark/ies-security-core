package com.sitepark.ies.security.core.usecase.token;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import com.sitepark.ies.security.core.domain.value.TokenType;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class CreateTokenResultTest {

  @Test
  void testEntityIsStored() {

    AccessToken token =
        AccessToken.builder()
            .id("1")
            .userId("user123")
            .name("Test Token")
            .createdAt(Instant.parse("2025-01-01T10:00:00Z"))
            .tokenType(TokenType.PRIVATE)
            .build();

    CreateTokenResult result = new CreateTokenResult(token, "generated-token");

    assertEquals(token, result.entity(), "Entity should match the provided AccessToken");
  }

  @Test
  void testTokenStringIsStored() {

    AccessToken token =
        AccessToken.builder()
            .id("1")
            .userId("user123")
            .name("Test Token")
            .createdAt(Instant.parse("2025-01-01T10:00:00Z"))
            .tokenType(TokenType.PRIVATE)
            .build();

    CreateTokenResult result = new CreateTokenResult(token, "generated-token");

    assertEquals("generated-token", result.token(), "Token should match the provided token string");
  }
}

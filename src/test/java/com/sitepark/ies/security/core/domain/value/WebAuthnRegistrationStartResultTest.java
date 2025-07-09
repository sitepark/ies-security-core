package com.sitepark.ies.security.core.domain.value;

import static org.junit.jupiter.api.Assertions.*;

import com.jparams.verifier.tostring.ToStringVerifier;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

@SuppressWarnings("PMD.UseConcurrentHashMap")
class WebAuthnRegistrationStartResultTest {
  @Test
  void testEquals() {
    EqualsVerifier.forClass(WebAuthnRegistrationStartResult.class).verify();
  }

  @Test
  void testToString() {
    ToStringVerifier.forClass(WebAuthnRegistrationStartResult.class).verify();
  }

  @Test
  void testNullPublicKeyOptions() {
    WebAuthnRegistrationStartResult result = new WebAuthnRegistrationStartResult(null);
    assertEquals(
        Collections.emptyMap(),
        result.publicKeyOptions(),
        "Expected publicKeyOptions to be empty when null is passed");
  }

  @Test
  void testImmutableInputPublicKeyOptions() {
    Map<String, Object> options = new HashMap<>();
    options.put("key", "value");
    WebAuthnRegistrationStartResult result = new WebAuthnRegistrationStartResult(options);
    options.put("a", "b");

    assertEquals(
        Map.of("key", "value"),
        result.publicKeyOptions(),
        "Expected publicKeyOptions to be immutable");
  }

  @Test
  void testImmutableOutputPublicKeyOptions() {
    Map<String, Object> options = new HashMap<>();
    options.put("key", "value");
    WebAuthnRegistrationStartResult result = new WebAuthnRegistrationStartResult(options);
    options.put("a", "b");

    assertThrows(
        UnsupportedOperationException.class,
        () -> {
          result.publicKeyOptions().put("newKey", "newValue");
        },
        "Expected publicKeyOptions to be immutable on output");
  }
}

package com.sitepark.ies.security.core.domain.value;

import static org.junit.jupiter.api.Assertions.*;

import com.jparams.verifier.tostring.ToStringVerifier;
import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

class PartialAuthenticationStateTest {

  @Test
  void testEquals() {
    EqualsVerifier.forClass(PartialAuthenticationState.class).verify();
  }

  @Test
  void testToString() {
    ToStringVerifier.forClass(PartialAuthenticationState.class).verify();
  }

  @Test
  void testSetNullRequirement() {
    PartialAuthenticationState state = new PartialAuthenticationState(null, null, null, null, null);
    assertNotNull(state.requirements(), "Requirements should not be null");
  }

  @Test
  void testImmutableRequirements() {
    AuthenticationRequirement[] requirements =
        new AuthenticationRequirement[] {AuthenticationRequirement.TOTP_CODE_REQUIRED};
    PartialAuthenticationState state =
        new PartialAuthenticationState(null, null, requirements, null, null);

    requirements[0] = AuthenticationRequirement.PASSKEY_CHALLENGE_REQUIRED;

    assertArrayEquals(
        new AuthenticationRequirement[] {AuthenticationRequirement.TOTP_CODE_REQUIRED},
        state.requirements(),
        "Requirements should be immutable");
  }
}

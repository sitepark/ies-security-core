package com.sitepark.ies.security.core.domain.value;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import org.junit.jupiter.api.Test;

class SystemAuthenticationSettingsTest {

  @Test
  void testDefaultAllowsTotpAndPasskey() {
    assertTrue(
        SystemAuthenticationSettings.DEFAULT.isAllowed(AuthFactorType.TOTP)
            && SystemAuthenticationSettings.DEFAULT.isAllowed(AuthFactorType.PASSKEY)
            && !SystemAuthenticationSettings.DEFAULT.isAllowed(AuthFactorType.EMAIL_CODE),
        "the default must keep today's behaviour");
  }

  @Test
  void testPasskeyMinimumWithoutPasskeysIsInvalid() {
    SystemAuthenticationSettings settings =
        new SystemAuthenticationSettings(
            Set.of(AuthFactorType.TOTP),
            new AuthenticationPolicy(AuthenticationPolicyLevel.PASSKEY, null));
    assertFalse(settings.isValid(), "a passkey minimum needs passkeys");
  }

  @Test
  void testSecondFactorMinimumWithoutFactorsIsInvalid() {
    SystemAuthenticationSettings settings =
        new SystemAuthenticationSettings(
            Set.of(), new AuthenticationPolicy(AuthenticationPolicyLevel.SECOND_FACTOR, null));
    assertFalse(settings.isValid(), "a second factor minimum needs a factor");
  }

  @Test
  void testSecondFactorCanBeMetWithPasskeysOnly() {
    SystemAuthenticationSettings settings =
        new SystemAuthenticationSettings(Set.of(AuthFactorType.PASSKEY), AuthenticationPolicy.NONE);
    assertTrue(
        settings.canMeet(AuthenticationPolicyLevel.SECOND_FACTOR),
        "a passkey login meets the second factor requirement");
  }
}

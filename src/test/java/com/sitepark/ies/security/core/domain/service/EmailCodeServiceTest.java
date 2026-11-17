package com.sitepark.ies.security.core.domain.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.value.EmailCodeLoginPayload;
import com.sitepark.ies.security.core.domain.value.VaultEntryNames;
import com.sitepark.ies.security.core.port.EmailCodeSender;
import com.sitepark.ies.security.core.port.Vault;
import com.sitepark.ies.security.core.port.VaultProvider;
import com.sitepark.ies.sharedkernel.security.CodeVerificationChallenge;
import com.sitepark.ies.sharedkernel.security.CodeVerificationFailedException;
import com.sitepark.ies.sharedkernel.security.CodeVerificationService;
import com.sitepark.ies.sharedkernel.security.User;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
class EmailCodeServiceTest {

  private static final Instant NOW = Instant.parse("2026-11-17T10:00:00Z");

  private final User user = User.builder().id("7").username("peter").lastName("Pan").build();

  private CodeVerificationService codeVerificationService;
  private Vault vault;
  private EmailCodeSender sender;
  private EmailCodeService service;

  @BeforeEach
  void setUp() {
    this.codeVerificationService = mock();
    this.vault = mock();
    this.sender = mock();
    VaultProvider vaultProvider = mock();
    when(vaultProvider.getUserVault("7")).thenReturn(this.vault);
    this.service = new EmailCodeService(this.codeVerificationService, vaultProvider, this.sender);
  }

  private CodeVerificationChallenge challenge(String userId, boolean sendCode) {
    return new CodeVerificationChallenge(
        "c-1", 123_456, new EmailCodeLoginPayload(userId), NOW, NOW.plusSeconds(600), 0, sendCode);
  }

  private void address() {
    when(this.vault.hasSecret(VaultEntryNames.EMAIL_CODE_ADDRESS)).thenReturn(true);
    when(this.vault.loadSecret(VaultEntryNames.EMAIL_CODE_ADDRESS)).thenReturn("peter@example.org");
  }

  @Test
  void testStartLoginWithoutAddress() {
    assertEquals(Optional.empty(), this.service.startLogin(this.user), "no address, no code");
  }

  @Test
  void testStartLoginSendsCode() {
    this.address();
    CodeVerificationChallenge challenge = this.challenge("7", true);
    when(this.codeVerificationService.startChallenge(any())).thenReturn(challenge);

    this.service.startLogin(this.user);

    verify(this.sender).send(this.user, "peter@example.org", challenge);
  }

  @Test
  void testStartLoginDoesNotSendRunningCodeAgain() {
    this.address();
    when(this.codeVerificationService.startChallenge(any())).thenReturn(this.challenge("7", false));

    this.service.startLogin(this.user);

    verify(this.sender, never()).send(any(), any(), any());
  }

  @Test
  void testResendSendsRunningCode() {
    this.address();
    CodeVerificationChallenge challenge = this.challenge("7", false);
    when(this.codeVerificationService.startChallenge(any())).thenReturn(challenge);

    this.service.resend(this.user);

    verify(this.sender).send(this.user, "peter@example.org", challenge);
  }

  @Test
  void testVerifyWrongCode() {
    when(this.codeVerificationService.finishChallenge("c-1", 1))
        .thenThrow(new CodeVerificationFailedException("wrong"));
    assertFalse(this.service.verify(this.user, "c-1", 1), "a wrong code must not verify");
  }

  @Test
  void testVerifyCodeOfOtherUser() {
    when(this.codeVerificationService.finishChallenge("c-1", 123_456))
        .thenReturn(this.challenge("8", true));
    assertFalse(
        this.service.verify(this.user, "c-1", 123_456), "a code of another user must not verify");
  }

  @Test
  void testVerify() {
    when(this.codeVerificationService.finishChallenge("c-1", 123_456))
        .thenReturn(this.challenge("7", true));
    assertTrue(this.service.verify(this.user, "c-1", 123_456), "the code of the user must verify");
  }
}

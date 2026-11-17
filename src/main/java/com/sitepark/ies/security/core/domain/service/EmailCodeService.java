package com.sitepark.ies.security.core.domain.service;

import com.sitepark.ies.security.core.domain.value.EmailCodeLoginPayload;
import com.sitepark.ies.security.core.domain.value.VaultEntryNames;
import com.sitepark.ies.security.core.port.EmailCodeSender;
import com.sitepark.ies.security.core.port.Vault;
import com.sitepark.ies.security.core.port.VaultProvider;
import com.sitepark.ies.sharedkernel.security.CodeVerificationChallenge;
import com.sitepark.ies.sharedkernel.security.CodeVerificationFailedException;
import com.sitepark.ies.sharedkernel.security.CodeVerificationService;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;
import java.util.Optional;

/**
 * Sends and checks the e-mail codes of logins. The codes go to the address the user confirmed when
 * setting up the e-mail code. The code verification service keeps one challenge per user, limits the
 * attempts and does not send the code of a running challenge again by itself.
 */
public class EmailCodeService {

  private final CodeVerificationService codeVerificationService;
  private final VaultProvider vaultProvider;
  private final EmailCodeSender emailCodeSender;

  @Inject
  protected EmailCodeService(
      CodeVerificationService codeVerificationService,
      VaultProvider vaultProvider,
      EmailCodeSender emailCodeSender) {
    this.codeVerificationService = codeVerificationService;
    this.vaultProvider = vaultProvider;
    this.emailCodeSender = emailCodeSender;
  }

  /** Starts the challenge of a login and sends its code; empty if the user has no confirmed address. */
  public Optional<String> startLogin(User user) {
    return this.address(user).map(address -> this.start(user, address, false).challengeId());
  }

  /** Sends the code of the running challenge of the user again. */
  public void resend(User user) {
    this.address(user).ifPresent(address -> this.start(user, address, true));
  }

  /** Returns whether the code belongs to the challenge of a login of the user. */
  public boolean verify(User user, String challengeId, int code) {
    CodeVerificationChallenge challenge;
    try {
      challenge = this.codeVerificationService.finishChallenge(challengeId, code);
    } catch (CodeVerificationFailedException e) {
      return false;
    }
    return challenge.payload() instanceof EmailCodeLoginPayload(String userId)
        && userId.equals(user.id());
  }

  private CodeVerificationChallenge start(User user, String address, boolean resend) {
    CodeVerificationChallenge challenge =
        this.codeVerificationService.startChallenge(new EmailCodeLoginPayload(user.id()));
    if (challenge.sendCode() || resend) {
      this.emailCodeSender.send(user, address, challenge);
    }
    return challenge;
  }

  private Optional<String> address(User user) {
    Vault vault = this.vaultProvider.getUserVault(user.id());
    if (!vault.hasSecret(VaultEntryNames.EMAIL_CODE_ADDRESS)) {
      return Optional.empty();
    }
    return Optional.of(vault.loadSecret(VaultEntryNames.EMAIL_CODE_ADDRESS));
  }
}

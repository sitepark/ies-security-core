package com.sitepark.ies.security.core.usecase.emailcode;

import com.sitepark.ies.security.core.domain.exception.AuthenticationProcessNotFoundException;
import com.sitepark.ies.security.core.domain.exception.EmailCodeNotRequiredException;
import com.sitepark.ies.security.core.domain.service.EmailCodeService;
import com.sitepark.ies.security.core.domain.value.AuthenticationRequirement;
import com.sitepark.ies.security.core.domain.value.PartialAuthenticationState;
import com.sitepark.ies.security.core.port.TotpAuthenticationProcessStore;
import jakarta.inject.Inject;

/**
 * Sends the e-mail code of a login again. Every call counts as an attempt of the login process,
 * which limits the number of e-mails one login can trigger.
 */
public class ResendEmailCodeUseCase {

  private final TotpAuthenticationProcessStore authenticationProcessStore;
  private final EmailCodeService emailCodeService;

  @Inject
  protected ResendEmailCodeUseCase(
      TotpAuthenticationProcessStore authenticationProcessStore,
      EmailCodeService emailCodeService) {
    this.authenticationProcessStore = authenticationProcessStore;
    this.emailCodeService = emailCodeService;
  }

  public void resendEmailCode(String authProcessId) {
    PartialAuthenticationState authState =
        this.authenticationProcessStore
            .retrieve(authProcessId)
            .orElseThrow(AuthenticationProcessNotFoundException::new);
    if (!authState.requirements().contains(AuthenticationRequirement.EMAIL_CODE_REQUIRED)) {
      throw new EmailCodeNotRequiredException();
    }
    this.emailCodeService.resend(authState.user());
  }
}

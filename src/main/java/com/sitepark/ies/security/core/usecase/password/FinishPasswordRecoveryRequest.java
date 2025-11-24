package com.sitepark.ies.security.core.usecase.password;

import com.sitepark.ies.sharedkernel.email.EmailAddress;
import com.sitepark.ies.sharedkernel.email.EmailMessage;
import java.util.List;

public record FinishPasswordRecoveryRequest(
    String challengeId,
    int code,
    String newPassword,
    EmailAddress from,
    List<EmailAddress> replyTo,
    EmailMessage message) {
  public FinishPasswordRecoveryRequest {
    replyTo = List.copyOf(replyTo);
  }
}

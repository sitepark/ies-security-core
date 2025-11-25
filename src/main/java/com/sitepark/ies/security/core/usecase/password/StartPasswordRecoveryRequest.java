package com.sitepark.ies.security.core.usecase.password;

import com.sitepark.ies.sharedkernel.email.EmailAddress;
import com.sitepark.ies.sharedkernel.email.EmailMessage;
import java.util.List;

public record StartPasswordRecoveryRequest(
    String username, EmailAddress from, List<EmailAddress> replyTo, EmailMessage message) {
  public StartPasswordRecoveryRequest {
    replyTo = List.copyOf(replyTo);
  }
}

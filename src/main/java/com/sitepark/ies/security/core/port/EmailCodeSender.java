package com.sitepark.ies.security.core.port;

import com.sitepark.ies.sharedkernel.security.CodeVerificationChallenge;
import com.sitepark.ies.sharedkernel.security.User;

/** Sends the code of a challenge to an e-mail address, for the login or to confirm the address. */
@FunctionalInterface
public interface EmailCodeSender {

  void send(User user, String address, CodeVerificationChallenge challenge);
}

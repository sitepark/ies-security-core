package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.entity.WebAuthnRegisteredCredential;
import com.sitepark.ies.security.core.domain.exception.WebAuthnChallengeExpiredException;
import com.sitepark.ies.security.core.domain.exception.WebAuthnException;
import com.sitepark.ies.security.core.domain.exception.WebAuthnInvalidRequestException;
import com.sitepark.ies.security.core.domain.exception.WebAuthnVerificationFailedException;
import com.sitepark.ies.security.core.domain.value.WebAuthnAssertionFinishResult;
import com.sitepark.ies.sharedkernel.security.User;
import java.net.URI;
import java.util.List;

public interface WebAuthnProvider {
  /**
   * Starts a registration.
   *
   * @throws WebAuthnException on internal failures
   */
  String startRegistration(User user, URI origin, String applicationName, String passkeyName);

  /**
   * Finishes a registration.
   *
   * @throws WebAuthnInvalidRequestException if the credential JSON cannot be parsed
   * @throws WebAuthnChallengeExpiredException if the challenge is missing or expired
   * @throws WebAuthnVerificationFailedException if the verification of the registration failed
   */
  void finishRegistration(String publicKeyCredentialJson);

  /**
   * Starts an assertion.
   *
   * @throws WebAuthnException on internal failures
   */
  String startAssertion(URI origin, String applicationName);

  /**
   * Finishes an assertion.
   *
   * @return the result; an unsuccessful verification may be reported as a result with success=false
   * @throws WebAuthnInvalidRequestException if the assertion JSON cannot be parsed
   * @throws WebAuthnChallengeExpiredException if the challenge is missing or expired
   * @throws WebAuthnVerificationFailedException if the verification of the assertion failed
   */
  WebAuthnAssertionFinishResult finishAssertion(String publicKeyCredentialJson);

  List<WebAuthnRegisteredCredential> findRegisteredCredentialByUserId(String userId);

  void removeRegisteredCredential(String id);

  String getUserIdById(String id);
}

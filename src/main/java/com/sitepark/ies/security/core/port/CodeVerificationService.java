package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.exception.CodeVerificationFailedException;
import com.sitepark.ies.security.core.domain.value.CodeVerificationChallenge;
import com.sitepark.ies.security.core.domain.value.CodeVerificationPayload;

/**
 * Service for managing code-based verification challenges. Supports secure verification processes
 * like newPassword recovery and user registration.
 */
public interface CodeVerificationService {

  /**
   * Initiates a verification challenge for a given payload.
   *
   * @param payload Contains identification information for the verification process
   * @return A challenge with a unique ID and verification code
   * @throws IllegalArgumentException if the payload is invalid
   */
  CodeVerificationChallenge startChallenge(CodeVerificationPayload payload);

  /**
   * Creates a fake verification challenge to prevent user enumeration. Used when no user is found
   * for the given identification.
   *
   * @return A challenge with a fake verification process
   */
  CodeVerificationChallenge createFakeChallenge();

  /**
   * Completes a verification challenge by validating the provided code.
   *
   * @param challengeId Unique identifier of the challenge
   * @param code Verification code to validate
   * @return The original challenge if verification is successful
   * @throws CodeVerificationFailedException if the code is invalid or the challenge cannot be
   *     completed
   */
  CodeVerificationChallenge finishChallenge(String challengeId, int code);
}

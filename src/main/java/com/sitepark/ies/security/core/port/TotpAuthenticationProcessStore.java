package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.value.PartialAuthenticationState;
import java.util.Optional;

/**
 * Stores partially completed authentication processes between the authentication steps.
 *
 * <p>The store is responsible for limiting validation attempts: the use case does not count failed
 * attempts itself.
 */
public interface TotpAuthenticationProcessStore {

  /**
   * Stores the state of an authentication process.
   *
   * @param state the state to store
   * @return a new, unguessable id of the authentication process
   */
  String store(PartialAuthenticationState state);

  /**
   * Retrieves an authentication process. Every retrieval counts as one validation attempt.
   *
   * <p>Returns an empty result once the process has expired or once a store-defined maximum number
   * of retrievals has been reached. The store may remove the process in that case.
   *
   * @param authProcessId the id returned by {@link #store(PartialAuthenticationState)}
   * @return the state, or empty if the process is unknown, expired or exhausted
   */
  Optional<PartialAuthenticationState> retrieve(String authProcessId);

  /**
   * Removes an authentication process. This operation is idempotent: removing an unknown or
   * already removed process has no effect.
   *
   * @param authProcessId the id of the process to remove
   */
  void remove(String authProcessId);
}

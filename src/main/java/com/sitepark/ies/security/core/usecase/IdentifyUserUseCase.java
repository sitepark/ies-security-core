package com.sitepark.ies.security.core.usecase;

import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.security.core.usecase.authentication.AuthenticationInfo;
import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Optional;

/**
 * First step in a multi-stage authentication process.
 *
 * <p>This use case is typically used as the first step in a multi-stage authentication process,
 * where the client provides a username or email address and receives a list of supported
 * authentication methods for that user (e.g., password, passkey, etc.).
 *
 * <p>To prevent disclosing whether a user exists in the system, this implementation returns a
 * generic set of default authentication methods even if the provided username or email does not
 * correspond to a registered user.
 *
 * <p>This approach helps prevent user enumeration attacks, where an attacker could probe the system
 * to discover valid usernames or email addresses based on different responses. Example:
 *
 * <ul>
 *   <li>Input: "existent" → Output: [PASSWORD, PASSKEY]
 *   <li>Input: "nonexistent" → Output: [PASSWORD]
 * </ul>
 *
 * In both cases, the API response is identical, making it impossible for clients to infer whether
 * the user exists.
 */
public class IdentifyUserUseCase {

  private final UserService userRepository;

  private static final AuthMethod[] DEFAULT_AUTH_METHODS = new AuthMethod[] {AuthMethod.PASSWORD};

  @Inject
  public IdentifyUserUseCase(UserService userRepository) {
    this.userRepository = userRepository;
  }

  public AuthenticationInfo identifyUser(String username) {
    Optional<User> user = this.userRepository.findByUsername(username);
    return user.map(value -> new AuthenticationInfo(value.authMethods()))
        .orElseGet(() -> new AuthenticationInfo(List.of(DEFAULT_AUTH_METHODS)));
  }
}

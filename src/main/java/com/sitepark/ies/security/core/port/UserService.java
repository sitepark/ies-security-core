package com.sitepark.ies.security.core.port;

import com.sitepark.ies.sharedkernel.security.AuthenticationContext;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.Optional;

public interface UserService {
  Optional<User> findById(String id);

  Optional<User> findByUsername(String username);

  Optional<String> getPasswordHash(String userId);

  void upgradePasswordHash(String username, String upgradedHash);

  /**
   * Users who log in via external systems may not yet have been created in this system or their
   * data may be out of date. This method synchronizes the user who has just logged in with the data
   * from the external system. This is the case, for example, when logging in via OAuth2.
   */
  Optional<User> syncAuthenticatedUser(AuthenticationContext context, User user);
}

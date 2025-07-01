package com.sitepark.ies.security.core.port;

import com.sitepark.ies.sharedkernel.security.User;
import java.util.Optional;

public interface UserService {
  Optional<User> findById(String id);

  Optional<User> findByUsername(String username);

  Optional<String> getPasswordHash(String userId);

  void upgradePasswordHash(String username, String upgradedHash);
}

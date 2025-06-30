package com.sitepark.ies.security.core.port;

import com.sitepark.ies.sharedkernel.security.User;
import java.util.Optional;

public interface UserService {
  Optional<User> findById(String id);

  Optional<User> findByUsername(String username);

  void upgradePasswordHash(String username, String upgradedHash);
}

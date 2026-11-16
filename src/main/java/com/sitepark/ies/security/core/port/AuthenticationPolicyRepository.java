package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.value.AuthenticationPolicy;
import java.util.Optional;

/** Stores the authentication policy of each user. Users without a stored policy have none. */
public interface AuthenticationPolicyRepository {

  Optional<AuthenticationPolicy> get(String userId);

  void set(String userId, AuthenticationPolicy policy);

  void remove(String userId);
}

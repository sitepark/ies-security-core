package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.value.PartialAuthenticationState;
import java.util.Optional;

public interface AuthenticationProcessStore {
  String store(PartialAuthenticationState state);

  Optional<PartialAuthenticationState> retrieve(String authProcessId);

  void remove(String sessionId);
}

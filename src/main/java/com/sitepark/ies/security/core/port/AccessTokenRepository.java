package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import java.util.Optional;

public interface AccessTokenRepository {

  AccessToken create(AccessToken accessToken);

  void revoke(String user, String id);

  void purge(String user, String id);

  void purgeByUser(String user);

  void touch(String user, String id);

  Optional<AccessToken> getByToken(String token);
}

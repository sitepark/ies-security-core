package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.entity.AccessToken;
import java.util.List;
import java.util.Optional;

public interface AccessTokenRepository {

  AccessToken create(AccessToken accessToken, String tokenDigest);

  void revoke(String id);

  void purge(String id);

  void purgeByUser(String user);

  void touch(String id);

  Optional<AccessToken> getByToken(String token);

  List<AccessToken> getPrivateTokens(String userId);

  List<AccessToken> getServiceTokens();

  List<AccessToken> getImpersonationTokens();
}

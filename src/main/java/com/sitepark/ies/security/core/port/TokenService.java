package com.sitepark.ies.security.core.port;

public interface TokenService {

  String generateToken();

  String digestToken(String token);
}

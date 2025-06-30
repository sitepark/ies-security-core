package com.sitepark.ies.security.core.port;

public interface TotpProvider {
  String generateSecret();

  boolean validateTotpCode(String secret, int totpCode);
}

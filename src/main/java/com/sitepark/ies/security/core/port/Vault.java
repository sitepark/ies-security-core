package com.sitepark.ies.security.core.port;

public interface Vault {

  void storeSecret(String name, String plainValue);

  boolean hasSecret(String name);

  void deleteSecret(String name);

  String loadSecret(String name);
}

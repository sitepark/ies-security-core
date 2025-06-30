package com.sitepark.ies.security.core.domain.value;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public record TotpUrl(String issuer, String account, String secret) {
  public TotpUrl {
    Objects.requireNonNull(issuer, "Issuer must not be null");
    if (issuer.isBlank()) {
      throw new IllegalArgumentException("Issuer must not be null or blank");
    }
    Objects.requireNonNull(account, "account must not be null");
    if (account.isBlank()) {
      throw new IllegalArgumentException("Account must not be null or blank");
    }
    Objects.requireNonNull(secret, "secret must not be null");
    if (secret.isBlank()) {
      throw new IllegalArgumentException("Secret must not be null or blank");
    }
  }

  @Override
  public String toString() {
    return String.format(
        "otpauth://totp/%s:%s?secret=%s&issuer=%s",
        urlEncode(issuer.trim()), urlEncode(account), secret, urlEncode(issuer));
  }

  private String urlEncode(String input) {
    return URLEncoder.encode(input, StandardCharsets.UTF_8);
  }
}

package com.sitepark.ies.security.core.domain.value;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

@SuppressWarnings("PMD.AvoidFieldNameMatchingMethodName")
public final class WebAuthnRegistrationStartResult {

  private final Map<String, Object> publicKeyOptions;

  public WebAuthnRegistrationStartResult(Map<String, Object> publicKeyOptions) {
    this.publicKeyOptions =
        publicKeyOptions == null ? Collections.emptyMap() : Map.copyOf(publicKeyOptions);
  }

  @JsonProperty
  public Map<String, Object> publicKeyOptions() {
    return Map.copyOf(this.publicKeyOptions);
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.publicKeyOptions);
  }

  @Override
  @SuppressWarnings("PMD.SimplifyBooleanReturns")
  public boolean equals(Object obj) {
    if (!(obj instanceof WebAuthnRegistrationStartResult that)) {
      return false;
    }
    return Objects.equals(this.publicKeyOptions, that.publicKeyOptions);
  }

  @Override
  public String toString() {
    return "WebAuthnRegistrationStartResult{" + "publicKeyOptions=" + publicKeyOptions + '}';
  }
}

package com.sitepark.ies.security.core.domain.value;

import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.User;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

public record PartialAuthenticationState(
    User user, AuthMethod method, AuthenticationRequirement[] requirements, Instant createdAt) {
  public PartialAuthenticationState(
      User user, AuthMethod method, AuthenticationRequirement[] requirements, Instant createdAt) {
    this.user = user;
    this.method = method;
    this.requirements =
        requirements != null ? requirements.clone() : new AuthenticationRequirement[] {};
    this.createdAt = createdAt;
  }

  @Override
  public AuthenticationRequirement[] requirements() {
    return requirements.clone();
  }

  @Override
  public int hashCode() {
    return Objects.hash(user, method, Arrays.hashCode(requirements), createdAt);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof PartialAuthenticationState that)) {
      return false;
    }
    return Objects.equals(this.user, that.user)
        && Objects.equals(this.method, that.method)
        && Arrays.equals(this.requirements, that.requirements)
        && Objects.equals(this.createdAt, that.createdAt);
  }

  @Override
  public String toString() {
    return "PartialAuthenticationState{"
        + "user="
        + user
        + ", method="
        + method
        + ", requirements="
        + Arrays.toString(requirements)
        + ", createdAt="
        + createdAt
        + '}';
  }
}

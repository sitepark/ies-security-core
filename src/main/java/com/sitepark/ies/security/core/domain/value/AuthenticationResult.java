package com.sitepark.ies.security.core.domain.value;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

@SuppressWarnings({"PMD.AvoidFieldNameMatchingMethodName", "PMD.TooManyMethods"})
public final class AuthenticationResult {

  private final AuthenticationStatus status;
  @Nullable private final User user;
  @Nullable private final String authProcessId; // für PARTIAL-Logins
  private final List<AuthenticationRequirement> requirements;
  @Nullable private final String purpose;

  private AuthenticationResult(
      AuthenticationStatus status,
      @Nullable User user,
      @Nullable String authProcessId,
      @Nullable List<AuthenticationRequirement> requirements,
      @Nullable String purpose) {
    this.status = status;
    this.user = user;
    this.authProcessId = authProcessId;
    this.requirements = requirements != null ? requirements : List.of();
    this.purpose = purpose;
  }

  @Override
  public int hashCode() {
    return Objects.hash(status, user, authProcessId, requirements, purpose);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof AuthenticationResult that)) {
      return false;
    }
    return Objects.equals(this.status, that.status)
        && Objects.equals(this.user, that.user)
        && Objects.equals(this.authProcessId, that.authProcessId)
        && Objects.equals(this.requirements, that.requirements)
        && Objects.equals(this.purpose, that.purpose);
  }

  @Override
  public String toString() {
    return "AuthenticationResult{"
        + "status="
        + status
        + ", user="
        + user
        + ", authProcessId='"
        + authProcessId
        + '\''
        + ", requirements="
        + requirements
        + ", purpose='"
        + purpose
        + '\''
        + '}';
  }

  public static AuthenticationResult success(User user, String purpose) {
    return new AuthenticationResult(AuthenticationStatus.SUCCESS, user, null, List.of(), purpose);
  }

  public static AuthenticationResult partial(
      String authProcessId, List<AuthenticationRequirement> requirements) {
    return new AuthenticationResult(
        AuthenticationStatus.PARTIAL, null, authProcessId, requirements, null);
  }

  public static AuthenticationResult failure() {
    return new AuthenticationResult(AuthenticationStatus.FAILURE, null, null, List.of(), null);
  }

  @JsonProperty
  public AuthenticationStatus status() {
    return status;
  }

  @JsonProperty
  public @Nullable User user() {
    return user;
  }

  @JsonProperty
  public @Nullable String authProcessId() {
    return authProcessId;
  }

  @JsonProperty
  public @Nullable String purpose() {
    return purpose;
  }

  @JsonProperty
  public List<AuthenticationRequirement> requirements() {
    return List.copyOf(requirements);
  }
}

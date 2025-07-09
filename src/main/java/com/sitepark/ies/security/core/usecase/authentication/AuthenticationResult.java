package com.sitepark.ies.security.core.usecase.authentication;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.sitepark.ies.security.core.domain.value.AuthenticationRequirement;
import com.sitepark.ies.security.core.domain.value.AuthenticationStatus;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.Arrays;
import java.util.Objects;

@SuppressWarnings({"PMD.AvoidFieldNameMatchingMethodName", "PMD.TooManyMethods"})
public final class AuthenticationResult {

  private final AuthenticationStatus status;
  private final User user;
  private final String authProcessId; // für PARTIAL-Logins
  private final AuthenticationRequirement[] requirements;
  private final String purpose;

  private AuthenticationResult(
      AuthenticationStatus status,
      User user,
      String authProcessId,
      AuthenticationRequirement[] requirements,
      String purpose) {
    this.status = status;
    this.user = user;
    this.authProcessId = authProcessId;
    this.requirements = requirements != null ? requirements : new AuthenticationRequirement[] {};
    this.purpose = purpose;
  }

  @Override
  public int hashCode() {
    return Objects.hash(status, user, authProcessId, Arrays.hashCode(requirements), purpose);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof AuthenticationResult that)) {
      return false;
    }
    return Objects.equals(this.status, that.status)
        && Objects.equals(this.user, that.user)
        && Objects.equals(this.authProcessId, that.authProcessId)
        && Arrays.equals(this.requirements, that.requirements)
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
        + Arrays.toString(requirements)
        + ", purpose='"
        + purpose
        + '\''
        + '}';
  }

  public static AuthenticationResult success(User user, String purpose) {
    return new AuthenticationResult(
        AuthenticationStatus.SUCCESS, user, null, new AuthenticationRequirement[] {}, purpose);
  }

  @SuppressWarnings("PMD.UseVarargs")
  public static AuthenticationResult partial(
      String authProcessId, AuthenticationRequirement[] requirements) {
    return new AuthenticationResult(
        AuthenticationStatus.PARTIAL, null, authProcessId, requirements, null);
  }

  public static AuthenticationResult failure() {
    return new AuthenticationResult(
        AuthenticationStatus.FAILURE, null, null, new AuthenticationRequirement[] {}, null);
  }

  @JsonProperty
  public AuthenticationStatus status() {
    return status;
  }

  @JsonProperty
  public User user() {
    return user;
  }

  @JsonProperty
  public String authProcessId() {
    return authProcessId;
  }

  @JsonProperty
  public String purpose() {
    return purpose;
  }

  @JsonProperty
  public AuthenticationRequirement[] requirements() {
    return requirements.clone();
  }
}

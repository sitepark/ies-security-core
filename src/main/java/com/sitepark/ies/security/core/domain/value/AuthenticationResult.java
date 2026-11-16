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
  @Nullable private final PolicyNotice policyNotice;
  @Nullable private final AuthenticationFailureReason failureReason;

  private AuthenticationResult(
      AuthenticationStatus status,
      @Nullable User user,
      @Nullable String authProcessId,
      @Nullable List<AuthenticationRequirement> requirements,
      @Nullable String purpose) {
    this(status, user, authProcessId, requirements, purpose, null, null);
  }

  private AuthenticationResult(
      AuthenticationStatus status,
      @Nullable User user,
      @Nullable String authProcessId,
      @Nullable List<AuthenticationRequirement> requirements,
      @Nullable String purpose,
      @Nullable PolicyNotice policyNotice,
      @Nullable AuthenticationFailureReason failureReason) {
    this.status = status;
    this.user = user;
    this.authProcessId = authProcessId;
    this.requirements = requirements != null ? requirements : List.of();
    this.purpose = purpose;
    this.policyNotice = policyNotice;
    this.failureReason = failureReason;
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        status, user, authProcessId, requirements, purpose, policyNotice, failureReason);
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
        && Objects.equals(this.purpose, that.purpose)
        && Objects.equals(this.policyNotice, that.policyNotice)
        && Objects.equals(this.failureReason, that.failureReason);
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
        + ", policyNotice="
        + policyNotice
        + ", failureReason="
        + failureReason
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

  /** A failed login whose credentials were correct but which the user's policy refuses. */
  public static AuthenticationResult failure(AuthenticationFailureReason reason) {
    Objects.requireNonNull(reason, "reason cannot be null");
    return new AuthenticationResult(
        AuthenticationStatus.FAILURE, null, null, List.of(), null, null, reason);
  }

  /** Returns a copy of this result that reminds the user of a coming requirement. */
  public AuthenticationResult withPolicyNotice(@Nullable PolicyNotice notice) {
    return new AuthenticationResult(
        this.status,
        this.user,
        this.authProcessId,
        this.requirements,
        this.purpose,
        notice,
        this.failureReason);
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

  @JsonProperty
  public @Nullable PolicyNotice policyNotice() {
    return policyNotice;
  }

  @JsonProperty
  public @Nullable AuthenticationFailureReason failureReason() {
    return failureReason;
  }
}

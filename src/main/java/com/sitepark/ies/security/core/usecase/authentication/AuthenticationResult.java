package com.sitepark.ies.security.core.usecase.authentication;

import com.sitepark.ies.security.core.domain.entity.AuthenticatedUser;
import com.sitepark.ies.security.core.domain.value.AuthenticationRequirement;
import com.sitepark.ies.security.core.domain.value.AuthenticationStatus;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

public final class AuthenticationResult {

  private final AuthenticationStatus status;
  private final AuthenticatedUser user;
  private final String authProcessId; // für PARTIAL-Logins
  private final AuthenticationRequirement[] requirements;

  @SuppressWarnings("PMD.UseVarargs")
  private AuthenticationResult(
      AuthenticationStatus status,
      AuthenticatedUser user,
      String authProcessId,
      AuthenticationRequirement[] requirements) {
    this.status = status;
    this.user = user;
    this.authProcessId = authProcessId;
    this.requirements = requirements != null ? requirements : new AuthenticationRequirement[] {};
  }

  @Override
  public int hashCode() {
    return Objects.hash(status, user, authProcessId, Arrays.hashCode(requirements));
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof AuthenticationResult that)) {
      return false;
    }
    return Objects.equals(this.status, that.status)
        && Objects.equals(this.user, that.user)
        && Objects.equals(this.authProcessId, that.authProcessId)
        && Arrays.equals(this.requirements, that.requirements);
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
        + '}';
  }

  public static AuthenticationResult success(AuthenticatedUser user) {
    return new AuthenticationResult(
        AuthenticationStatus.SUCCESS, user, null, new AuthenticationRequirement[] {});
  }

  @SuppressWarnings("PMD.UseVarargs")
  public static AuthenticationResult partial(
      String authProcessId, AuthenticationRequirement[] requirements) {
    return new AuthenticationResult(
        AuthenticationStatus.PARTIAL, null, authProcessId, requirements);
  }

  public static AuthenticationResult failure() {
    return new AuthenticationResult(
        AuthenticationStatus.FAILURE, null, null, new AuthenticationRequirement[] {});
  }

  public AuthenticationStatus getStatus() {
    return status;
  }

  public Optional<AuthenticatedUser> getUser() {
    return Optional.ofNullable(user);
  }

  public Optional<String> getAuthProcessId() {
    return Optional.ofNullable(authProcessId);
  }

  public AuthenticationRequirement[] getRequirements() {
    return requirements.clone();
  }
}

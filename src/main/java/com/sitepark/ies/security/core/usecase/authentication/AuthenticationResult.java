package com.sitepark.ies.security.core.usecase.authentication;

import com.sitepark.ies.security.core.domain.entity.AuthenticatedUser;
import com.sitepark.ies.security.core.domain.value.AuthenticationRequirement;
import com.sitepark.ies.security.core.domain.value.AuthenticationStatus;
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

package com.sitepark.ies.security.core.domain.value;

import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.User;
import java.time.OffsetDateTime;

@SuppressWarnings("PMD.DataClass")
public class PartialAuthenticationState {
  private final User user;
  private final AuthMethod method;
  private final AuthenticationRequirement[] requirements;
  private final OffsetDateTime createdAt;

  public PartialAuthenticationState(
      User user,
      AuthMethod method,
      AuthenticationRequirement[] requirements,
      OffsetDateTime createdAt) {
    this.user = user;
    this.method = method;
    this.requirements = requirements != null ? requirements : new AuthenticationRequirement[] {};
    this.createdAt = createdAt;
  }

  public User getUser() {
    return user;
  }

  public String getUserId() {
    return user.getId();
  }

  public AuthMethod getMethod() {
    return method;
  }

  public AuthenticationRequirement[] getRequirements() {
    return requirements.clone();
  }

  public OffsetDateTime getCreatedAt() {
    return createdAt;
  }
}

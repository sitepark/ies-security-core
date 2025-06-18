package com.sitepark.ies.security.core.domain.entity;

import com.sitepark.ies.sharedkernel.security.Authentication;
import com.sitepark.ies.sharedkernel.security.FullAccess;
import com.sitepark.ies.sharedkernel.security.Permission;
import java.util.List;

public class SystemAuthentication implements Authentication {

  private final String purpose;

  private final List<Permission> permissions = List.of(new FullAccess());

  public SystemAuthentication(String purpose) {
    this.purpose = purpose;
  }

  @Override
  public String getName() {
    return "System";
  }

  @Override
  public String getPurpose() {
    return this.purpose;
  }

  @Override
  public boolean isAuthenticated() {
    return true;
  }

  @Override
  public void eraseCredentials() {}

  @Override
  public List<Permission> getPermissions() {
    return this.permissions;
  }
}

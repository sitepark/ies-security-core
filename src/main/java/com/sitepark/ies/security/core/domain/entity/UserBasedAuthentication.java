package com.sitepark.ies.security.core.domain.entity;

import com.sitepark.ies.sharedkernel.security.Authentication;
import com.sitepark.ies.sharedkernel.security.Permission;
import java.util.List;

public class UserBasedAuthentication implements Authentication {

  private final AuthenticatedUser user;

  private final List<Permission> permissions;

  private final String purpose;

  public UserBasedAuthentication(
      AuthenticatedUser user, List<Permission> permissions, String purpose) {
    this.user = user;
    this.permissions = List.copyOf(permissions);
    this.purpose = purpose;
  }

  public AuthenticatedUser getUser() {
    return user;
  }

  @Override
  public String getName() {
    StringBuilder name = new StringBuilder();
    if (user.getFirstName() != null && !user.getFirstName().isEmpty()) {
      name.append(user.getFirstName()).append(' ');
    }
    name.append(user.getLastName());

    return name.toString();
  }

  @Override
  public String getPurpose() {
    return purpose;
  }

  @Override
  public List<Permission> getPermissions() {
    return this.permissions;
  }
}

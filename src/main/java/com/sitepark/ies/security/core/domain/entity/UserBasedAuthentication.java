package com.sitepark.ies.security.core.domain.entity;

import com.sitepark.ies.sharedkernel.security.Authentication;
import com.sitepark.ies.sharedkernel.security.Permission;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

@SuppressWarnings("PMD.AvoidFieldNameMatchingMethodName")
public final class UserBasedAuthentication implements Authentication {

  private final User user;

  private final List<Permission> permissions;

  private final String purpose;

  private UserBasedAuthentication(Builder builder) {
    this.user = builder.user;
    this.permissions = List.copyOf(builder.permissions);
    this.purpose = builder.purpose;
  }

  public User user() {
    return user;
  }

  @Override
  @NotNull
  public String name() {
    return user.getName();
  }

  @Override
  @NotNull
  public String purpose() {
    return purpose;
  }

  @Override
  @NotNull
  public List<Permission> permissions() {
    return this.permissions;
  }

  @Override
  public int hashCode() {
    return Objects.hash(user, permissions, purpose);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof UserBasedAuthentication that)) {
      return false;
    }
    return Objects.equals(this.user, that.user)
        && Objects.equals(this.permissions, that.permissions)
        && Objects.equals(this.purpose, that.purpose);
  }

  @Override
  public String toString() {
    return "UserBasedAuthentication{"
        + "user="
        + user
        + ", permissions="
        + permissions
        + ", purpose='"
        + purpose
        + '\''
        + '}';
  }

  public static Builder builder() {
    return new Builder();
  }

  public static final class Builder {

    private User user;

    private final List<Permission> permissions = new ArrayList<>();

    private String purpose;

    private Builder() {}

    public Builder user(User user) {
      Objects.requireNonNull(user, "user must not be null");
      this.user = user;
      return this;
    }

    public Builder permissions(List<Permission> permissions) {
      Objects.requireNonNull(permissions, "permissions must not be null");
      for (Permission permission : permissions) {
        this.permission(permission);
      }
      return this;
    }

    public Builder permission(Permission permission) {
      Objects.requireNonNull(permission, "permission must not be null");
      this.permissions.add(permission);
      return this;
    }

    public Builder purpose(String purpose) {
      this.purpose = purpose;
      return this;
    }

    public UserBasedAuthentication build() {
      Objects.requireNonNull(user, "user must not be null");
      Objects.requireNonNull(purpose, "purpose must not be null");
      return new UserBasedAuthentication(this);
    }
  }
}

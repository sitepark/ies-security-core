package com.sitepark.ies.security.core.domain.entity;

import com.sitepark.ies.sharedkernel.security.Permission;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public final class UserTokenAuthentication implements UserBasedAuthentication {

  private final String name;

  private final boolean authenticated;

  private final String token;

  private final String tokenName;

  private final AuthenticatedUser user;

  private final List<Permission> permissions;

  private UserTokenAuthentication(Builder builder) {
    this.name = builder.name;
    this.authenticated = builder.authenticated;
    this.token = builder.token;
    this.user = builder.user;
    this.tokenName = builder.tokenName;
    this.permissions = Collections.unmodifiableList(builder.permissions);
  }

  public String getToken() {
    return this.token;
  }

  public String getTokenName() {
    return this.tokenName;
  }

  @Override
  public String getPurpose() {
    return this.getTokenName();
  }

  @Override
  public String getName() {
    return this.name;
  }

  @Override
  public boolean isAuthenticated() {
    return this.authenticated;
  }

  @Override
  public List<Permission> getPermissions() {
    return this.permissions;
  }

  @Override
  public void eraseCredentials() {}

  @Override
  public AuthenticatedUser getUser() {
    return this.user;
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  public static Builder builder() {
    return new Builder();
  }

  public static final class Builder {

    private String name;

    private boolean authenticated;

    private String token;

    private String tokenName;

    private AuthenticatedUser user;

    private final List<Permission> permissions = new ArrayList<>();

    private Builder() {}

    private Builder(UserTokenAuthentication authentication) {
      this.name = authentication.name;
      this.authenticated = authentication.authenticated;
      this.token = authentication.token;
      this.tokenName = authentication.tokenName;
      this.user = authentication.user;
      this.permissions.addAll(authentication.permissions);
    }

    public Builder authenticated(boolean authenticated) {
      this.authenticated = authenticated;
      return this;
    }

    public Builder token(String token) {
      this.token = token;
      return this;
    }

    public Builder tokenName(String tokenName) {
      this.tokenName = tokenName;
      return this;
    }

    public Builder user(AuthenticatedUser user) {
      this.user = user;
      return this;
    }

    public Builder permissions(List<Permission> permissions) {
      Objects.requireNonNull(permissions, "permissions is null");
      for (Permission permission : permissions) {
        this.permission(permission);
      }
      return this;
    }

    public Builder permissions(Permission... permissions) {
      Objects.requireNonNull(permissions, "permissions is null");
      for (Permission permission : permissions) {
        this.permission(permission);
      }
      return this;
    }

    public Builder permission(Permission permission) {
      Objects.requireNonNull(permission, "permission is null");
      this.permissions.add(permission);
      return this;
    }

    public UserTokenAuthentication build() {
      if (this.user != null) {
        this.name = this.user.getName();
      } else if (this.tokenName != null) {
        this.name = "Token(" + this.tokenName + ")";
      }
      return new UserTokenAuthentication(this);
    }
  }
}

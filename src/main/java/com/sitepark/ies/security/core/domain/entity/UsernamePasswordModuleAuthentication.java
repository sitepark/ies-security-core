package com.sitepark.ies.security.core.domain.entity;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.sitepark.ies.sharedkernel.security.Permission;
import java.util.*;

@JsonDeserialize(builder = UsernamePasswordModuleAuthentication.Builder.class)
public final class UsernamePasswordModuleAuthentication implements UserBasedAuthentication {

  private final String name;

  private final boolean authenticated;

  private final String username;

  private String password;

  private final String module;

  private final AuthenticatedUser user;

  private final List<Permission> permissions;

  private UsernamePasswordModuleAuthentication(Builder builder) {
    this.name = builder.name;
    this.authenticated = builder.authenticated;
    this.username = builder.username;
    this.password = builder.password;
    this.module = builder.module;
    this.user = builder.user;
    this.permissions = Collections.unmodifiableList(builder.permissions);
  }

  public String getUsername() {
    return this.username;
  }

  public Optional<String> getPassword() {
    return Optional.ofNullable(this.password);
  }

  @Override
  public String getName() {
    return this.name;
  }

  public String getModule() {
    return this.module;
  }

  @Override
  public String getPurpose() {
    return this.module;
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
  @SuppressWarnings(("PMD.NullAssignment"))
  public void eraseCredentials() {
    this.password = null;
  }

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

  @JsonPOJOBuilder(withPrefix = "", buildMethodName = "build")
  public static final class Builder {

    private String name;

    private boolean authenticated;

    private String username;

    private String password;

    private String module;

    private AuthenticatedUser user;

    private final List<Permission> permissions = new ArrayList<>();

    private Builder() {}

    private Builder(UsernamePasswordModuleAuthentication authentication) {
      this.authenticated = authentication.authenticated;
      this.username = authentication.username;
      this.password = authentication.password;
      this.module = authentication.module;
      this.user = authentication.user;
      this.permissions.addAll(authentication.permissions);
    }

    public Builder authenticated(boolean authenticated) {
      this.authenticated = authenticated;
      return this;
    }

    public Builder username(String username) {
      Objects.requireNonNull(username, "username is null");
      this.username = username;
      return this;
    }

    public Builder password(String password) {
      this.password = password;
      return this;
    }

    public Builder module(String module) {
      this.module = module;
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

    public UsernamePasswordModuleAuthentication build() {
      Objects.requireNonNull(username, "username is null");
      this.name = this.username;
      if (this.user != null) {
        this.name = this.user.getName();
      }
      Objects.requireNonNull(module, "module is null");
      return new UsernamePasswordModuleAuthentication(this);
    }
  }
}

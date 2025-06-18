package com.sitepark.ies.security.core.domain.entity;

import com.sitepark.ies.sharedkernel.security.Permission;
import java.util.*;

public final class SessionIdAuthentication implements UserBasedAuthentication {

  private final String name;

  private final boolean authenticated;

  private final long sessionId;

  private final AuthenticatedUser user;

  private final String module;

  private final List<Permission> permissions;

  private SessionIdAuthentication(Builder builder) {
    this.name = builder.name;
    this.authenticated = builder.authenticated;
    this.sessionId = builder.sessionId;
    this.user = builder.user;
    this.module = builder.module;
    this.permissions = Collections.unmodifiableList(builder.permissions);
  }

  public long getSessionId() {
    return this.sessionId;
  }

  public String getModule() {
    return this.module;
  }

  @Override
  public String getPurpose() {
    return this.module;
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

    private long sessionId;

    private String module;

    private AuthenticatedUser user;

    private final List<Permission> permissions = new ArrayList<>();

    private Builder() {}

    private Builder(SessionIdAuthentication authentication) {
      this.name = authentication.name;
      this.authenticated = authentication.authenticated;
      this.sessionId = authentication.sessionId;
      this.module = authentication.module;
      this.user = authentication.user;
      this.permissions.addAll(authentication.permissions);
    }

    public Builder authenticated(boolean authenticated) {
      this.authenticated = authenticated;
      return this;
    }

    public Builder sessionId(long sessionId) {
      this.sessionId = sessionId;
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
        this.permissions(permission);
      }
      return this;
    }

    public Builder permissions(Permission... permissions) {
      Objects.requireNonNull(permissions, "permissions is null");
      for (Permission permission : permissions) {
        this.permissions(permission);
      }
      return this;
    }

    public Builder permission(Permission permission) {
      Objects.requireNonNull(permission, "permission is null");
      this.permissions.add(permission);
      return this;
    }

    public SessionIdAuthentication build() {
      if (this.user != null) {
        this.name = this.user.getName();
      } else {
        this.name = "Session(" + this.sessionId + ")";
      }
      assert this.module != null : "module is null";
      return new SessionIdAuthentication(this);
    }
  }
}

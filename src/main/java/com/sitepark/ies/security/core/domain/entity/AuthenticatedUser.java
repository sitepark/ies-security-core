package com.sitepark.ies.security.core.domain.entity;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import java.util.Objects;

@JsonDeserialize(builder = AuthenticatedUser.Builder.class)
public final class AuthenticatedUser {

  private final String id;

  private final String name;

  private final String login;

  private AuthenticatedUser(Builder builder) {
    this.id = builder.id;
    this.name = builder.name;
    this.login = builder.login;
  }

  public String getId() {
    return this.id;
  }

  public String getName() {
    return this.name;
  }

  public String getLogin() {
    return this.login;
  }

  public static Builder builder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    return this.name + " (" + this.id + ")";
  }

  @JsonPOJOBuilder(withPrefix = "", buildMethodName = "build")
  public static final class Builder {

    private String id;

    private String name;

    private String login;

    private Builder() {}

    private Builder(AuthenticatedUser user) {
      this.id = user.id;
      this.name = user.name;
      this.login = user.login;
    }

    public Builder id(String id) {
      Objects.requireNonNull(id, "id cannot be null");
      this.id = id;
      return this;
    }

    public Builder name(String name) {
      Objects.requireNonNull(name, "name cannot be null");
      this.name = name;
      return this;
    }

    public Builder login(String login) {
      Objects.requireNonNull(login, "login cannot be null");
      this.login = login;
      return this;
    }

    public AuthenticatedUser build() {
      Objects.requireNonNull(id, "id cannot be null");
      Objects.requireNonNull(name, "name cannot be null");
      Objects.requireNonNull(login, "login cannot be null");
      return new AuthenticatedUser(this);
    }
  }
}

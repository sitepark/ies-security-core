package com.sitepark.ies.security.core.domain.entity;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.sitepark.ies.sharedkernel.security.AuthFactor;
import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.Arrays;
import java.util.Objects;

@JsonDeserialize(builder = AuthenticatedUser.Builder.class)
public final class AuthenticatedUser {

  private final String id;
  private final String username;
  private final String firstName;
  private final String lastName;
  private final String email;
  private final AuthMethod[] authMethods;
  private final AuthFactor[] authFactors;

  private AuthenticatedUser(Builder builder) {
    this.id = builder.id;
    this.username = builder.username;
    this.firstName = builder.firstName;
    this.lastName = builder.lastName;
    this.email = builder.email;
    this.authMethods = builder.authMethods;
    this.authFactors = builder.authFactors;
  }

  public String getId() {
    return this.id;
  }

  public String getUsername() {
    return this.username;
  }

  public String getFirstName() {
    return this.firstName;
  }

  public String getLastName() {
    return this.lastName;
  }

  public String getEmail() {
    return this.email;
  }

  public AuthMethod[] getAuthMethods() {
    return this.authMethods.clone();
  }

  public AuthFactor[] getAuthFactor() {
    return this.authFactors.clone();
  }

  public static AuthenticatedUser fromUser(User user) {
    return builder()
        .id(user.getId())
        .username(user.getUsername())
        .firstName(user.getFirstName())
        .lastName(user.getLastName())
        .email(user.getEmail())
        .authMethods(user.getAuthMethods())
        .authFactors(user.getAuthFactors())
        .build();
  }

  public static Builder builder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        id,
        username,
        firstName,
        lastName,
        email,
        Arrays.hashCode(authMethods),
        Arrays.hashCode(authFactors));
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof AuthenticatedUser that)) {
      return false;
    }
    return Objects.equals(this.id, that.id)
        && Objects.equals(this.username, that.username)
        && Objects.equals(this.firstName, that.firstName)
        && Objects.equals(this.lastName, that.lastName)
        && Objects.equals(this.email, that.email)
        && Arrays.equals(this.authMethods, that.authMethods)
        && Arrays.equals(this.authFactors, that.authFactors);
  }

  @Override
  public String toString() {
    return "AuthenticatedUser{"
        + "id='"
        + id
        + '\''
        + ", username='"
        + username
        + '\''
        + ", firstName='"
        + firstName
        + '\''
        + ", lastName='"
        + lastName
        + '\''
        + ", email='"
        + email
        + '\''
        + ", authMethods="
        + Arrays.toString(authMethods)
        + ", authFactors="
        + Arrays.toString(authFactors)
        + '}';
  }

  @JsonPOJOBuilder(withPrefix = "")
  public static final class Builder {

    private String id;
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private AuthMethod[] authMethods;
    private AuthFactor[] authFactors;

    private Builder() {}

    private Builder(AuthenticatedUser user) {
      this.id = user.id;
      this.username = user.username;
      this.firstName = user.firstName;
      this.lastName = user.lastName;
      this.email = user.email;
      this.authMethods = user.authMethods.clone();
      this.authFactors = user.authFactors.clone();
    }

    public Builder id(String id) {
      Objects.requireNonNull(id, "id cannot be null");
      this.id = id;
      return this;
    }

    public Builder username(String username) {
      Objects.requireNonNull(username, "username cannot be null");
      this.username = username;
      return this;
    }

    public Builder firstName(String firstName) {
      Objects.requireNonNull(firstName, "firstName cannot be null");
      this.firstName = firstName;
      return this;
    }

    public Builder lastName(String lastName) {
      Objects.requireNonNull(lastName, "lastName cannot be null");
      this.lastName = lastName;
      return this;
    }

    public Builder email(String email) {
      Objects.requireNonNull(email, "email cannot be null");
      this.email = email;
      return this;
    }

    public Builder authMethods(AuthMethod... authMethods) {
      Objects.requireNonNull(authMethods, "authMethods cannot be null");
      this.authMethods = authMethods.clone();
      return this;
    }

    public Builder authFactors(AuthFactor... authFactors) {
      Objects.requireNonNull(authFactors, "authFactors cannot be null");
      this.authFactors = authFactors.clone();
      return this;
    }

    public AuthenticatedUser build() {
      Objects.requireNonNull(id, "id cannot be null");
      Objects.requireNonNull(username, "username cannot be null");
      Objects.requireNonNull(lastName, "lastName cannot be null");
      if (this.authMethods == null) {
        this.authMethods = new AuthMethod[] {};
      }
      if (this.authFactors == null) {
        this.authFactors = new AuthFactor[] {};
      }
      return new AuthenticatedUser(this);
    }
  }
}

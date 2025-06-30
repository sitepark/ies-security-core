package com.sitepark.ies.security.core.domain.entity;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.sitepark.ies.sharedkernel.security.AuthFactor;
import com.sitepark.ies.sharedkernel.security.AuthMethod;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

@SuppressWarnings({"PMD.AvoidFieldNameMatchingMethodName", "PMD.TooManyMethods"})
@JsonDeserialize(builder = AuthenticatedUser.Builder.class)
public final class AuthenticatedUser {

  private final String id;
  private final String username;
  private final String firstName;
  private final String lastName;
  private final String email;
  private final List<AuthMethod> authMethods;
  private final List<AuthFactor> authFactors;

  public AuthenticatedUser(Builder builder) {
    this.id = builder.id;
    this.username = builder.username;
    this.firstName = builder.firstName;
    this.lastName = builder.lastName;
    this.email = builder.email;
    this.authMethods = List.copyOf(builder.authMethods);
    this.authFactors = List.copyOf(builder.authFactors);
  }

  public String id() {
    return id;
  }

  public String username() {
    return username;
  }

  public String firstName() {
    return firstName;
  }

  public String lastName() {
    return lastName;
  }

  public String email() {
    return email;
  }

  public List<AuthMethod> authMethods() {
    return authMethods;
  }

  public List<AuthFactor> authFactors() {
    return authFactors;
  }

  public String getName() {
    StringBuilder name = new StringBuilder();
    if (firstName != null && !firstName.trim().isBlank()) {
      name.append(firstName.trim());
    }
    if (!name.isEmpty()) {
      name.append(' ');
    }
    name.append(lastName.trim());
    return name.toString();
  }

  public static AuthenticatedUser fromUser(User user) {
    return builder()
        .id(user.id())
        .username(user.username())
        .lastName(user.lastName())
        .firstName(user.firstName())
        .email(user.email())
        .authMethods(user.authMethods())
        .authFactors(user.authFactors())
        .build();
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, username, firstName, lastName, email, authMethods, authFactors);
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
        && Objects.equals(this.authMethods, that.authMethods)
        && Objects.equals(this.authFactors, that.authFactors);
  }

  @Override
  public String toString() {
    return "User{"
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
        + authMethods
        + ", authFactors="
        + authFactors
        + '}';
  }

  public static Builder builder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  @JsonPOJOBuilder(withPrefix = "")
  public static final class Builder {

    private String id;
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private final List<AuthMethod> authMethods = new ArrayList<>();
    private final List<AuthFactor> authFactors = new ArrayList<>();

    private Builder() {}

    private Builder(AuthenticatedUser user) {
      this.id = user.id;
      this.username = user.username;
      this.firstName = user.firstName;
      this.lastName = user.lastName;
      this.email = user.email;
      this.authMethods.addAll(user.authMethods);
      this.authFactors.addAll(user.authFactors);
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
      this.firstName = firstName;
      return this;
    }

    public Builder lastName(String lastName) {
      Objects.requireNonNull(lastName, "lastName cannot be null");
      this.lastName = lastName;
      return this;
    }

    public Builder email(String email) {
      this.email = email;
      return this;
    }

    @JsonSetter
    public Builder authMethods(Collection<AuthMethod> authMethods) {
      Objects.requireNonNull(authMethods, "authMethods cannot be null");
      for (AuthMethod authMethod : authMethods) {
        this.authMethod(authMethod);
      }
      return this;
    }

    public Builder authMethods(AuthMethod... authMethods) {
      Objects.requireNonNull(authMethods, "authMethods cannot be null");
      for (AuthMethod authMethod : authMethods) {
        this.authMethod(authMethod);
      }
      return this;
    }

    public Builder authMethod(AuthMethod authMethod) {
      Objects.requireNonNull(authMethod, "authMethod cannot be null");
      this.authMethods.add(authMethod);
      return this;
    }

    @JsonSetter
    public Builder authFactors(Collection<AuthFactor> authFactors) {
      Objects.requireNonNull(authFactors, "authFactors cannot be null");
      for (AuthFactor authFactor : authFactors) {
        this.authFactor(authFactor);
      }
      return this;
    }

    public Builder authFactors(AuthFactor... authFactors) {
      Objects.requireNonNull(authFactors, "authFactors cannot be null");
      for (AuthFactor authFactor : authFactors) {
        this.authFactor(authFactor);
      }
      return this;
    }

    public Builder authFactor(AuthFactor authFactor) {
      Objects.requireNonNull(authFactor, "authFactor cannot be null");
      this.authFactors.add(authFactor);
      return this;
    }

    public AuthenticatedUser build() {
      Objects.requireNonNull(id, "id cannot be null");
      Objects.requireNonNull(username, "username cannot be null");
      Objects.requireNonNull(lastName, "lastName cannot be null");
      if (lastName.trim().isBlank()) {
        throw new IllegalArgumentException("lastName cannot be blank");
      }
      return new AuthenticatedUser(this);
    }
  }
}

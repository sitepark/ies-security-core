package com.sitepark.ies.security.core.domain.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.sitepark.ies.security.core.domain.value.TokenType;
import com.sitepark.ies.sharedkernel.base.ListBuilder;
import com.sitepark.ies.sharedkernel.security.Permission;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import org.jspecify.annotations.Nullable;

/**
 * An access token enables authentication as a user without specifying a username and newPassword.
 */
@JsonDeserialize(builder = AccessToken.Builder.class)
@SuppressWarnings({"PMD.AvoidFieldNameMatchingMethodName", "PMD.TooManyMethods"})
public final class AccessToken {

  @Nullable private final String id;

  @Nullable private final String userId;

  private final String name;

  @Nullable private final Instant createdAt;

  @Nullable private final Instant expiresAt;

  @Nullable private final Instant lastUsedAt;

  private final List<Permission> permissions;

  private final TokenType tokenType;

  private final boolean active;

  private final boolean revoked;

  private AccessToken(Builder builder) {
    this.id = builder.id;
    this.userId = builder.userId;
    this.name = Objects.requireNonNull(builder.name, "name is null");
    this.createdAt = builder.createdAt;
    this.expiresAt = builder.expiresAt;
    this.lastUsedAt = builder.lastUsedAt;
    this.permissions = List.copyOf(builder.permissions);
    this.tokenType = Objects.requireNonNull(builder.tokenType, "tokenType is null");
    this.active = builder.active;
    this.revoked = builder.revoked;
  }

  @JsonProperty
  public @Nullable String id() {
    return this.id;
  }

  @JsonProperty
  public @Nullable String userId() {
    return this.userId;
  }

  @JsonProperty
  public String name() {
    return this.name;
  }

  @JsonProperty
  public @Nullable Instant createdAt() {
    return this.createdAt;
  }

  @JsonProperty
  public @Nullable Instant expiresAt() {
    return this.expiresAt;
  }

  @JsonProperty
  public @Nullable Instant lastUsedAt() {
    return this.lastUsedAt;
  }

  @JsonProperty
  public List<Permission> permissions() {
    return List.copyOf(this.permissions);
  }

  @JsonProperty
  public TokenType tokenType() {
    return this.tokenType;
  }

  @JsonProperty
  public boolean active() {
    return this.active;
  }

  @JsonProperty
  public boolean revoked() {
    return this.revoked;
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
        this.id,
        this.userId,
        this.name,
        this.createdAt,
        this.expiresAt,
        this.lastUsedAt,
        this.permissions,
        this.tokenType,
        this.active,
        this.revoked);
  }

  @Override
  public boolean equals(Object o) {

    if (!(o instanceof AccessToken that)) {
      return false;
    }

    return Objects.equals(this.id, that.id)
        && Objects.equals(this.userId, that.userId)
        && Objects.equals(this.name, that.name)
        && Objects.equals(this.createdAt, that.createdAt)
        && Objects.equals(this.expiresAt, that.expiresAt)
        && Objects.equals(this.lastUsedAt, that.lastUsedAt)
        && Objects.equals(this.permissions, that.permissions)
        && Objects.equals(this.tokenType, that.tokenType)
        && this.active == that.active
        && this.revoked == that.revoked;
  }

  @Override
  public String toString() {
    return "AccessToken{"
        + "id='"
        + id
        + '\''
        + ", userId='"
        + userId
        + '\''
        + ", name='"
        + name
        + '\''
        + ", createdAt="
        + createdAt
        + ", expiresAt="
        + expiresAt
        + ", lastUsedAt="
        + lastUsedAt
        + ", permissions="
        + permissions
        + ", tokenType="
        + tokenType
        + ", active="
        + active
        + ", revoked="
        + revoked
        + '}';
  }

  @SuppressWarnings("PMD.TooManyMethods")
  @JsonPOJOBuilder(withPrefix = "")
  public static final class Builder {

    @Nullable private String id;

    @Nullable private String userId;

    @Nullable private String name;

    @Nullable private Instant createdAt;

    @Nullable private Instant expiresAt;

    @Nullable private Instant lastUsedAt;

    private final List<Permission> permissions = new ArrayList<>();

    @Nullable private TokenType tokenType;

    private boolean active = true;

    private boolean revoked;

    private Builder() {}

    private Builder(AccessToken accessToken) {
      this.id = accessToken.id;
      this.userId = accessToken.userId;
      this.name = accessToken.name;
      this.createdAt = accessToken.createdAt;
      this.expiresAt = accessToken.expiresAt;
      this.lastUsedAt = accessToken.lastUsedAt;
      this.permissions.addAll(accessToken.permissions);
      this.tokenType = accessToken.tokenType;
      this.active = accessToken.active;
      this.revoked = accessToken.revoked;
    }

    public Builder id(String id) {
      Objects.requireNonNull(id, "id is null");
      this.id = id;
      return this;
    }

    public Builder userId(String userId) {
      Objects.requireNonNull(userId, "userId is null");
      this.userId = userId;
      return this;
    }

    public Builder name(String name) {
      Objects.requireNonNull(name, "name is null");
      this.requireNonBlank(name, "name is blank");
      this.name = name;
      return this;
    }

    public Builder createdAt(@Nullable Instant createdAt) {
      this.createdAt = createdAt;
      return this;
    }

    public Builder expiresAt(@Nullable Instant expiresAt) {
      this.expiresAt = expiresAt;
      return this;
    }

    public Builder lastUsedAt(@Nullable Instant lastUsedAt) {
      this.lastUsedAt = lastUsedAt;
      return this;
    }

    public Builder permissions(Consumer<ListBuilder<Permission>> configurer) {
      ListBuilder<Permission> listBuilder = new ListBuilder<>();
      configurer.accept(listBuilder);
      this.permissions.clear();
      this.permissions.addAll(listBuilder.build());
      return this;
    }

    @JsonSetter
    public Builder permissions(List<Permission> permissions) {
      return this.permissions(list -> list.addAll(permissions));
    }

    public Builder tokenType(TokenType tokenType) {
      this.tokenType = tokenType;
      return this;
    }

    public Builder active(boolean active) {
      this.active = active;
      return this;
    }

    public Builder revoked(boolean revoked) {
      this.revoked = revoked;
      return this;
    }

    public AccessToken build() {
      return new AccessToken(this);
    }

    private void requireNonBlank(String s, String message) {
      if (s.isBlank()) {
        throw new IllegalArgumentException(message);
      }
    }
  }
}

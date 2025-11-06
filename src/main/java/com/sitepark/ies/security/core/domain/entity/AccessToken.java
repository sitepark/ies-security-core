package com.sitepark.ies.security.core.domain.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.sitepark.ies.security.core.domain.value.TokenType;
import com.sitepark.ies.sharedkernel.base.ListBuilder;
import com.sitepark.ies.sharedkernel.security.PermissionPayload;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/** An access token enables authentication as a user without specifying a username and password. */
@JsonDeserialize(builder = AccessToken.Builder.class)
@SuppressWarnings({"PMD.AvoidFieldNameMatchingMethodName", "PMD.TooManyMethods"})
public final class AccessToken {

  private final String id;

  @NotNull private final String userId;

  @NotNull private final String name;

  @Nullable private final Instant createdAt;

  @Nullable private final Instant expiresAt;

  @Nullable private final Instant lastUsed;

  @NotNull private final List<PermissionPayload> permissions;

  private final TokenType tokenType;

  private final boolean active;

  private final boolean revoked;

  private AccessToken(Builder builder) {
    this.id = builder.id;
    this.userId = builder.userId;
    this.name = builder.name;
    this.createdAt = builder.createdAt;
    this.expiresAt = builder.expiresAt;
    this.lastUsed = builder.lastUsed;
    this.permissions = List.copyOf(builder.permissions);
    this.tokenType = builder.tokenType;
    this.active = builder.active;
    this.revoked = builder.revoked;

    Objects.requireNonNull(this.name, "name is null");
    Objects.requireNonNull(this.tokenType, "tokenType is null");
  }

  @JsonProperty
  public String id() {
    return this.id;
  }

  @JsonProperty
  public String userId() {
    return this.userId;
  }

  @JsonProperty
  public String name() {
    return this.name;
  }

  @JsonProperty
  public Instant createdAt() {
    return this.createdAt;
  }

  @JsonProperty
  public Instant expiresAt() {
    return this.expiresAt;
  }

  @JsonProperty
  public Instant lastUsed() {
    return this.lastUsed;
  }

  @JsonProperty
  public List<PermissionPayload> permissions() {
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
        this.lastUsed,
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
        && Objects.equals(this.lastUsed, that.lastUsed)
        && Objects.equals(this.permissions, that.permissions)
        && Objects.equals(this.tokenType, that.tokenType)
        && Objects.equals(this.active, that.active)
        && Objects.equals(this.revoked, that.revoked);
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
        + ", lastUsed="
        + lastUsed
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

    private String id;

    private String userId;

    private String name;

    private Instant createdAt;

    private Instant expiresAt;

    private Instant lastUsed;

    private final List<PermissionPayload> permissions = new ArrayList<>();

    private TokenType tokenType;

    private boolean active = true;

    private boolean revoked;

    private Builder() {}

    private Builder(AccessToken accessToken) {
      this.id = accessToken.id;
      this.userId = accessToken.userId;
      this.name = accessToken.name;
      this.createdAt = accessToken.createdAt;
      this.expiresAt = accessToken.expiresAt;
      this.lastUsed = accessToken.lastUsed;
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

    public Builder createdAt(Instant createdAt) {
      this.createdAt = createdAt;
      return this;
    }

    public Builder expiresAt(Instant expiresAt) {
      this.expiresAt = expiresAt;
      return this;
    }

    public Builder lastUsed(Instant lastUsed) {
      this.lastUsed = lastUsed;
      return this;
    }

    public Builder permissions(Consumer<ListBuilder<PermissionPayload>> configurer) {
      ListBuilder<PermissionPayload> listBuilder = new ListBuilder<>();
      configurer.accept(listBuilder);
      this.permissions.clear();
      this.permissions.addAll(listBuilder.build());
      return this;
    }

    @JsonSetter
    public Builder permissions(List<PermissionPayload> permissions) {
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

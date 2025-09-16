package com.sitepark.ies.security.core.domain.entity;

import com.sitepark.ies.sharedkernel.security.UserBasedAuthentication;
import java.time.Instant;
import java.util.Objects;

@SuppressWarnings("PMD.AvoidFieldNameMatchingMethodName")
public final class Session {

  private final String id;

  private final Instant createdAt;

  private final UserBasedAuthentication authentication;

  private Session(Builder builder) {
    this.id = builder.id;
    this.createdAt = builder.createdAt;
    this.authentication = builder.authentication;
  }

  public String id() {
    return this.id;
  }

  public Instant createdAt() {
    return this.createdAt;
  }

  public UserBasedAuthentication authentication() {
    return this.authentication;
  }

  public static Builder builder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, createdAt, authentication);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof Session that)) {
      return false;
    }
    return Objects.equals(id, that.id)
        && Objects.equals(createdAt, that.createdAt)
        && Objects.equals(authentication, that.authentication);
  }

  @Override
  public String toString() {
    return "Session{"
        + "id='"
        + id
        + '\''
        + ", createdAt="
        + createdAt
        + ", authentication="
        + authentication
        + '}';
  }

  public static final class Builder {

    private String id;

    private Instant createdAt;

    private UserBasedAuthentication authentication;

    private Builder() {}

    private Builder(Session session) {
      this.id = session.id;
      this.createdAt = session.createdAt;
      this.authentication = session.authentication;
    }

    public Builder id(String id) {
      Objects.requireNonNull(id, "Session ID cannot be null");
      if (id.isBlank()) {
        throw new IllegalArgumentException("Session ID must be greater than 0");
      }
      this.id = id;
      return this;
    }

    public Builder createdAt(Instant createdAt) {
      Objects.requireNonNull(createdAt, "createdAt cannot be null");
      this.createdAt = createdAt;
      return this;
    }

    public Builder authentication(UserBasedAuthentication authentication) {
      Objects.requireNonNull(authentication, "authentication cannot be null");
      this.authentication = authentication;
      return this;
    }

    public Session build() {
      return new Session(this);
    }
  }
}

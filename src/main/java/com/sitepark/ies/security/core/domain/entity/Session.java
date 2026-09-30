package com.sitepark.ies.security.core.domain.entity;

import com.sitepark.ies.sharedkernel.security.UserAuthentication;
import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

@SuppressWarnings("PMD.AvoidFieldNameMatchingMethodName")
public final class Session {

  @Nullable private final String id;

  @Nullable private final Instant createdAt;

  @Nullable private final UserAuthentication authentication;

  private final String purpose;

  private Session(Builder builder) {
    this.id = builder.id;
    this.createdAt = builder.createdAt;
    this.authentication = builder.authentication;
    this.purpose = Objects.requireNonNull(builder.purpose, "purpose cannot be null");
  }

  public @Nullable String id() {
    return this.id;
  }

  public @Nullable Instant createdAt() {
    return this.createdAt;
  }

  public @Nullable UserAuthentication authentication() {
    return this.authentication;
  }

  public String purpose() {
    return this.purpose;
  }

  public static Builder builder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, createdAt, authentication, purpose);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof Session that)) {
      return false;
    }
    return Objects.equals(id, that.id)
        && Objects.equals(createdAt, that.createdAt)
        && Objects.equals(authentication, that.authentication)
        && Objects.equals(purpose, that.purpose);
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
        + ", purpose='"
        + purpose
        + '\''
        + '}';
  }

  public static final class Builder {

    @Nullable private String id;

    @Nullable private Instant createdAt;

    @Nullable private UserAuthentication authentication;

    @Nullable private String purpose;

    private Builder() {}

    private Builder(Session session) {
      this.id = session.id;
      this.createdAt = session.createdAt;
      this.authentication = session.authentication;
      this.purpose = session.purpose;
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

    public Builder authentication(UserAuthentication authentication) {
      Objects.requireNonNull(authentication, "authentication cannot be null");
      this.authentication = authentication;
      return this;
    }

    public Builder purpose(String purpose) {
      Objects.requireNonNull(purpose, "purpose cannot be null");
      if (purpose.isBlank()) {
        throw new IllegalArgumentException("purpose must not be blank");
      }
      this.purpose = purpose;
      return this;
    }

    public Session build() {
      return new Session(this);
    }
  }
}

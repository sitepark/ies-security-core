package com.sitepark.ies.security.core.domain.entity;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.sitepark.ies.sharedkernel.security.Authentication;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.util.Objects;

@JsonDeserialize(builder = Session.Builder.class)
public final class Session {

  private final long id;

  private final Authentication authentication;

  private Session(Builder builder) {
    this.id = builder.id;
    this.authentication = builder.authentication;
  }

  public long getId() {
    return this.id;
  }

  @SuppressFBWarnings("EI_EXPOSE_REP") // TODO
  public Authentication getAuthentication() {
    return this.authentication;
  }

  public static Builder builder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    return this.id + " [" + this.authentication + "]";
  }

  @JsonPOJOBuilder(withPrefix = "", buildMethodName = "build")
  public static final class Builder {

    private long id;

    private Authentication authentication;

    private Builder() {}

    private Builder(Session session) {
      this.id = session.id;
      this.authentication = session.authentication;
    }

    public Builder id(long id) {
      if (id <= 0) {
        throw new IllegalArgumentException("Session ID must be greater than 0");
      }
      this.id = id;
      return this;
    }

    @SuppressFBWarnings("EI_EXPOSE_REP2") // TODO
    public Builder authentication(Authentication authentication) {
      Objects.requireNonNull(authentication, "authentication cannot be null");
      this.authentication = authentication;
      return this;
    }

    public Session build() {
      return new Session(this);
    }
  }
}

package com.sitepark.ies.security.core.usecase;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@JsonDeserialize(builder = SetUserPasswordRequest.Builder.class)
@SuppressWarnings({"PMD.AvoidFieldNameMatchingMethodName"})
public final class SetUserPasswordRequest {

  @NotNull private final String userId;

  @NotNull private final String newPassword;

  @Nullable private final String auditParentId;

  private SetUserPasswordRequest(Builder builder) {
    this.userId = builder.userId;
    this.newPassword = builder.newPassword;
    this.auditParentId = builder.auditParentId;
  }

  public static Builder builder() {
    return new Builder();
  }

  @NotNull
  public String userId() {
    return this.userId;
  }

  @NotNull
  public String newPassword() {
    return this.newPassword;
  }

  @Nullable
  public String auditParentId() {
    return this.auditParentId;
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.userId, this.newPassword, this.auditParentId);
  }

  @Override
  public boolean equals(Object o) {
    return (o instanceof SetUserPasswordRequest that)
        && Objects.equals(this.userId, that.userId)
        && Objects.equals(this.newPassword, that.newPassword)
        && Objects.equals(this.auditParentId, that.auditParentId);
  }

  @Override
  public String toString() {
    return "SetUserPasswordRequest{"
        + "userId="
        + userId
        + ", newPassword=******"
        + ", auditParentId='"
        + auditParentId
        + '\''
        + '}';
  }

  @JsonPOJOBuilder(withPrefix = "")
  public static final class Builder {

    private String userId;

    private String newPassword;

    private String auditParentId;

    private Builder() {}

    private Builder(SetUserPasswordRequest builder) {
      this.userId = builder.userId;
      this.newPassword = builder.newPassword;
      this.auditParentId = builder.auditParentId;
    }

    public Builder userId(String userId) {
      this.userId = userId;
      return this;
    }

    public Builder newPassword(String newPassword) {
      this.newPassword = newPassword;
      return this;
    }

    public Builder auditParentId(String auditParentId) {
      this.auditParentId = auditParentId;
      return this;
    }

    public SetUserPasswordRequest build() {
      Objects.requireNonNull(this.userId, "userId must not be null");
      Objects.requireNonNull(this.newPassword, "newPassword must not be null");
      return new SetUserPasswordRequest(this);
    }
  }
}

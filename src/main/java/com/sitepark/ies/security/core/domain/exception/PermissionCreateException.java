package com.sitepark.ies.security.core.domain.exception;

import java.io.Serial;

public class PermissionCreateException extends RuntimeException {

  @Serial private static final long serialVersionUID = 1L;

  private final String permissionType;

  private final String permissionData;

  public PermissionCreateException(String permissionType, String permissionData, String message) {
    this(permissionType, permissionData, message, null);
  }

  public PermissionCreateException(
      String permissionType, String permissionData, String message, Throwable cause) {
    super(message, cause);
    this.permissionType = permissionType;
    this.permissionData = permissionData;
  }

  public String getPermissionType() {
    return this.permissionType;
  }

  public String getPermissionData() {
    return this.permissionData;
  }
}

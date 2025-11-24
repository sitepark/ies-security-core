package com.sitepark.ies.security.core.usecase.password;

import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.service.SetPasswordService;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import jakarta.inject.Inject;

public class SetUserPasswordUseCase {

  private final SetPasswordService setPasswordService;

  private final AccessControl accessControl;

  @Inject
  protected SetUserPasswordUseCase(
      SetPasswordService setPasswordService, AccessControl accessControl) {
    this.setPasswordService = setPasswordService;
    this.accessControl = accessControl;
  }

  public void setUserPassword(SetUserPasswordRequest request) {

    if (!this.accessControl.isSetPasswordAllowed(request.userId())) {
      throw new AccessDeniedException(
          "Not allowed to set newPassword for user " + request.userId());
    }

    this.setPasswordService.setPassword(request.userId(), request.newPassword());
  }
}

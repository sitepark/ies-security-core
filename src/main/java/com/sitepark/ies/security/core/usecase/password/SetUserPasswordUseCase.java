package com.sitepark.ies.security.core.usecase.password;

import com.sitepark.ies.security.core.port.AccessControl;
import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import com.sitepark.ies.sharedkernel.security.PasswordEncoder;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;

public class SetUserPasswordUseCase {

  private final UserService userService;

  private final AccessControl accessControl;

  private final PasswordEncoder passwordEncoder;

  @Inject
  protected SetUserPasswordUseCase(
      UserService userService, AccessControl accessControl, PasswordEncoder passwordEncoder) {
    this.userService = userService;
    this.accessControl = accessControl;
    this.passwordEncoder = passwordEncoder;
  }

  public void setUserPassword(SetUserPasswordRequest request) {

    if (!this.accessControl.isSetPasswordAllowed(request.userId())) {
      throw new AccessDeniedException("Not allowed to set password for user " + request.userId());
    }

    User user =
        this.userService
            .findById(request.userId())
            .orElseThrow(
                () ->
                    new IllegalArgumentException(
                        "User with id " + request.userId() + " not found"));

    String encodedPassword = this.passwordEncoder.encode(request.newPassword());
    this.userService.upgradePasswordHash(user.username(), encodedPassword);
  }
}

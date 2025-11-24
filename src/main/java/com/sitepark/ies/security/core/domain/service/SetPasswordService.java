package com.sitepark.ies.security.core.domain.service;

import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.PasswordEncoder;
import com.sitepark.ies.sharedkernel.security.User;
import jakarta.inject.Inject;

public class SetPasswordService {
  private final UserService userService;

  private final PasswordEncoder passwordEncoder;

  @Inject
  SetPasswordService(UserService userService, PasswordEncoder passwordEncoder) {
    this.userService = userService;
    this.passwordEncoder = passwordEncoder;
  }

  public void setPassword(String userId, String newPassword) {
    User user =
        this.userService
            .findById(userId)
            .orElseThrow(
                () -> new IllegalArgumentException("User with id " + userId + " not found"));

    String encodedPassword = this.passwordEncoder.encode(newPassword);
    this.userService.upgradePasswordHash(user.username(), encodedPassword);
  }
}

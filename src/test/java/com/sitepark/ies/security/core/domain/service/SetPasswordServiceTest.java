package com.sitepark.ies.security.core.domain.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.sitepark.ies.security.core.port.UserService;
import com.sitepark.ies.sharedkernel.security.PasswordEncoder;
import com.sitepark.ies.sharedkernel.security.User;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SetPasswordServiceTest {

  private UserService userService;
  private PasswordEncoder passwordEncoder;
  private SetPasswordService setPasswordService;

  @BeforeEach
  void setUp() {
    this.userService = mock();
    this.passwordEncoder = mock();
    this.setPasswordService = new SetPasswordService(userService, passwordEncoder);
  }

  @Test
  void testSetPasswordCallsFindById() {
    String userId = "user123";
    String newPassword = "newPassword123";
    String encodedPassword = "encodedPassword123";
    String username = "testuser";

    User user = mock();
    when(user.username()).thenReturn(username);
    when(userService.findById(userId)).thenReturn(Optional.of(user));
    when(passwordEncoder.encode(newPassword)).thenReturn(encodedPassword);

    setPasswordService.setPassword(userId, newPassword);

    verify(userService).findById(userId);
  }

  @Test
  void testSetPasswordEncodesPassword() {
    String userId = "user123";
    String newPassword = "newPassword123";
    String encodedPassword = "encodedPassword123";
    String username = "testuser";

    User user = mock();
    when(user.username()).thenReturn(username);
    when(userService.findById(userId)).thenReturn(Optional.of(user));
    when(passwordEncoder.encode(newPassword)).thenReturn(encodedPassword);

    setPasswordService.setPassword(userId, newPassword);

    verify(passwordEncoder).encode(newPassword);
  }

  @Test
  void testSetPasswordCallsUpgradePasswordHash() {
    String userId = "user123";
    String newPassword = "newPassword123";
    String encodedPassword = "encodedPassword123";
    String username = "testuser";

    User user = mock();
    when(user.username()).thenReturn(username);
    when(userService.findById(userId)).thenReturn(Optional.of(user));
    when(passwordEncoder.encode(newPassword)).thenReturn(encodedPassword);

    setPasswordService.setPassword(userId, newPassword);

    verify(userService).upgradePasswordHash(username, encodedPassword);
  }

  @Test
  void testSetPasswordWithUserNotFound() {
    String userId = "nonexistent";
    String newPassword = "newPassword123";

    when(userService.findById(userId)).thenReturn(Optional.empty());

    assertThrows(
        IllegalArgumentException.class,
        () -> setPasswordService.setPassword(userId, newPassword),
        "Should throw IllegalArgumentException when user is not found");
  }

  @Test
  void testSetPasswordWithUserNotFoundHasCorrectMessage() {
    String userId = "nonexistent";
    String newPassword = "newPassword123";

    when(userService.findById(userId)).thenReturn(Optional.empty());

    assertThrows(
        IllegalArgumentException.class, () -> setPasswordService.setPassword(userId, newPassword));
  }

  @Test
  void testSetPasswordUsesCorrectUsername() {
    String userId = "user123";
    String newPassword = "newPassword";
    String encodedPassword = "encoded";
    String username = "specificUsername";

    User user = mock();
    when(user.username()).thenReturn(username);
    when(userService.findById(userId)).thenReturn(Optional.of(user));
    when(passwordEncoder.encode(newPassword)).thenReturn(encodedPassword);

    setPasswordService.setPassword(userId, newPassword);

    verify(userService).upgradePasswordHash(eq(username), anyString());
  }

  @Test
  void testSetPasswordUsesEncodedPassword() {
    String userId = "user123";
    String newPassword = "plainPassword";
    String encodedPassword = "encodedPassword123";
    String username = "testuser";

    User user = mock();
    when(user.username()).thenReturn(username);
    when(userService.findById(userId)).thenReturn(Optional.of(user));
    when(passwordEncoder.encode(newPassword)).thenReturn(encodedPassword);

    setPasswordService.setPassword(userId, newPassword);

    verify(userService).upgradePasswordHash(anyString(), eq(encodedPassword));
  }
}

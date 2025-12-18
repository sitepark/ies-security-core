package com.sitepark.ies.security.core.usecase.password;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sitepark.ies.security.core.domain.service.AccessControl;
import com.sitepark.ies.security.core.domain.service.SetPasswordService;
import com.sitepark.ies.sharedkernel.security.AccessDeniedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SetUserPasswordUseCaseTest {

  private SetPasswordService setPasswordService;
  private AccessControl accessControl;

  private SetUserPasswordUseCase useCase;

  @BeforeEach
  void setUp() {
    this.setPasswordService = mock();
    this.accessControl = mock();

    this.useCase = new SetUserPasswordUseCase(this.setPasswordService, this.accessControl);
  }

  @Test
  void testAccessDenied() {

    when(this.accessControl.isSetPasswordAllowed("user123")).thenReturn(false);

    SetUserPasswordRequest request =
        SetUserPasswordRequest.builder().userId("user123").newPassword("newPass123").build();

    assertThrows(
        AccessDeniedException.class,
        () -> {
          this.useCase.setUserPassword(request);
        },
        "Should throw AccessDeniedException when user is not allowed to set password");
  }

  @Test
  void testVerifyAccessControlCalled() {

    when(this.accessControl.isSetPasswordAllowed("user123")).thenReturn(true);

    SetUserPasswordRequest request =
        SetUserPasswordRequest.builder().userId("user123").newPassword("newPass123").build();

    this.useCase.setUserPassword(request);

    verify(this.accessControl).isSetPasswordAllowed("user123");
  }

  @Test
  void testVerifySetPasswordServiceCalled() {

    when(this.accessControl.isSetPasswordAllowed("user123")).thenReturn(true);

    SetUserPasswordRequest request =
        SetUserPasswordRequest.builder().userId("user123").newPassword("newPass123").build();

    this.useCase.setUserPassword(request);

    verify(this.setPasswordService).setPassword("user123", "newPass123");
  }

  @Test
  void testSetPasswordWithDifferentUserId() {

    when(this.accessControl.isSetPasswordAllowed("user456")).thenReturn(true);

    SetUserPasswordRequest request =
        SetUserPasswordRequest.builder().userId("user456").newPassword("anotherPass").build();

    this.useCase.setUserPassword(request);

    verify(this.setPasswordService).setPassword("user456", "anotherPass");
  }
}

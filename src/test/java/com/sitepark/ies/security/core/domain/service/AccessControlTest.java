package com.sitepark.ies.security.core.domain.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.sitepark.ies.security.core.port.WebAuthnProvider;
import com.sitepark.ies.sharedkernel.security.Authentication;
import com.sitepark.ies.sharedkernel.security.User;
import com.sitepark.ies.sharedkernel.security.UserAuthentication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AccessControlTest {

  private Authentication authentication;
  private WebAuthnProvider webAuthnProvider;
  private AccessControl accessControl;

  @BeforeEach
  void setUp() {
    this.authentication = mock();
    this.webAuthnProvider = mock();
    this.accessControl = new AccessControl(() -> authentication, webAuthnProvider);
  }

  @Test
  void testIsImpersonationTokensManageableWithFullAccess() {
    when(this.authentication.hasFullAccess()).thenReturn(true);

    boolean result = accessControl.isImpersonationTokensManageable();

    assertTrue(result, "Should be manageable when user has full access");
  }

  @Test
  void testIsImpersonationTokensManageableWithoutFullAccess() {
    when(this.authentication.hasFullAccess()).thenReturn(false);
    boolean result = accessControl.isImpersonationTokensManageable();

    assertFalse(result, "Should not be manageable when user does not have full access");
  }

  @Test
  void testIsImpersonationTokensManageableWithNullAuthentication() {
    AccessControl accessControl = new AccessControl(() -> null, this.webAuthnProvider);

    boolean result = accessControl.isImpersonationTokensManageable();

    assertFalse(result, "Should not be manageable when authentication is null");
  }

  @Test
  void testIsGenerateTotpUrlAllowedAsAuthenticatedUser() {
    User user = mock();
    when(user.id()).thenReturn("user123");
    UserAuthentication userAuth = mock();
    when(userAuth.user()).thenReturn(user);
    AccessControl accessControl = new AccessControl(() -> userAuth, this.webAuthnProvider);

    boolean result = accessControl.isGenerateTotpUrlAllowed("user123");

    assertTrue(result, "Should be allowed for authenticated user");
  }

  @Test
  void testIsGenerateTotpUrlAllowedWithFullAccess() {
    when(this.authentication.hasFullAccess()).thenReturn(true);

    boolean result = accessControl.isGenerateTotpUrlAllowed("user123");

    assertTrue(result, "Should be allowed with full access");
  }

  @Test
  void testIsGenerateTotpUrlAllowedForDifferentUser() {
    User user = mock();
    when(user.id()).thenReturn("user123");
    UserAuthentication userAuth = mock();
    when(userAuth.user()).thenReturn(user);
    when(userAuth.hasFullAccess()).thenReturn(false);
    AccessControl accessControl = new AccessControl(() -> userAuth, this.webAuthnProvider);

    boolean result = accessControl.isGenerateTotpUrlAllowed("user456");

    assertFalse(result, "Should not be allowed for different user without full access");
  }

  @Test
  void testIsRemoveTotpSecretAllowedAsAuthenticatedUser() {
    User user = mock();
    when(user.id()).thenReturn("user123");
    UserAuthentication userAuth = mock();
    when(userAuth.user()).thenReturn(user);
    AccessControl accessControl = new AccessControl(() -> userAuth, this.webAuthnProvider);

    boolean result = accessControl.isRemoveTotpSecretAllowed("user123");

    assertTrue(result, "Should be allowed for authenticated user");
  }

  @Test
  void testIsRemoveTotpSecretAllowedWithFullAccess() {
    when(this.authentication.hasFullAccess()).thenReturn(true);

    boolean result = accessControl.isRemoveTotpSecretAllowed("user123");

    assertTrue(result, "Should be allowed with full access");
  }

  @Test
  void testIsWebAuthnRegistrationAllowedAsAuthenticatedUser() {
    User user = mock();
    when(user.id()).thenReturn("user123");
    UserAuthentication userAuth = mock();
    when(userAuth.user()).thenReturn(user);
    AccessControl accessControl = new AccessControl(() -> userAuth, this.webAuthnProvider);

    boolean result = accessControl.isWebAuthnRegistrationAllowed("user123");

    assertTrue(result, "Should be allowed for authenticated user");
  }

  @Test
  void testIsWebAuthnRegistrationAllowedWithFullAccess() {
    when(this.authentication.hasFullAccess()).thenReturn(true);

    boolean result = accessControl.isWebAuthnRegistrationAllowed("user123");

    assertTrue(result, "Should be allowed with full access");
  }

  @Test
  void testIsWebAuthnGetRegisteredCredentialsAllowedAsAuthenticatedUser() {
    User user = mock();
    when(user.id()).thenReturn("user123");
    UserAuthentication userAuth = mock();
    when(userAuth.user()).thenReturn(user);
    AccessControl accessControl = new AccessControl(() -> userAuth, this.webAuthnProvider);

    boolean result = accessControl.isWebAuthnGetRegisteredCredentialsAllowed("user123");

    assertTrue(result, "Should be allowed for authenticated user");
  }

  @Test
  void testIsWebAuthnGetRegisteredCredentialsAllowedWithFullAccess() {
    when(this.authentication.hasFullAccess()).thenReturn(true);

    boolean result = accessControl.isWebAuthnGetRegisteredCredentialsAllowed("user123");

    assertTrue(result, "Should be allowed with full access");
  }

  @Test
  void testIsWebAuthnRemoveRegisteredCredentialsAllowedAsAuthenticatedUser() {
    User user = mock();
    when(user.id()).thenReturn("user123");
    UserAuthentication userAuth = mock();
    when(userAuth.user()).thenReturn(user);
    AccessControl accessControl = new AccessControl(() -> userAuth, this.webAuthnProvider);
    when(webAuthnProvider.getUserIdById("cred123")).thenReturn("user123");

    boolean result = accessControl.isWebAuthnRemoveRegisteredCredentialsAllowed("cred123");

    assertTrue(result, "Should be allowed for authenticated user");
  }

  @Test
  void testIsWebAuthnRemoveRegisteredCredentialsAllowedWithFullAccess() {
    when(this.authentication.hasFullAccess()).thenReturn(true);
    when(webAuthnProvider.getUserIdById("cred123")).thenReturn("user123");

    boolean result = accessControl.isWebAuthnRemoveRegisteredCredentialsAllowed("cred123");

    assertTrue(result, "Should be allowed with full access");
  }

  @Test
  void testIsWebAuthnRemoveRegisteredCredentialsAllowedWithNullUserId() {
    when(webAuthnProvider.getUserIdById("cred123")).thenReturn(null);

    boolean result = accessControl.isWebAuthnRemoveRegisteredCredentialsAllowed("cred123");

    assertFalse(result, "Should not be allowed when userId is null");
  }

  @Test
  void testIsWebAuthnRemoveRegisteredCredentialsAllowedForDifferentUser() {
    User user = mock();
    when(user.id()).thenReturn("user123");
    UserAuthentication userAuth = mock();
    when(userAuth.user()).thenReturn(user);
    when(userAuth.hasFullAccess()).thenReturn(false);
    AccessControl accessControl = new AccessControl(() -> userAuth, this.webAuthnProvider);
    when(webAuthnProvider.getUserIdById("cred123")).thenReturn("user456");

    boolean result = accessControl.isWebAuthnRemoveRegisteredCredentialsAllowed("cred123");

    assertFalse(result, "Should not be allowed for different user without full access");
  }

  @Test
  void testIsSetPasswordAllowedAsAuthenticatedUser() {
    User user = mock();
    when(user.id()).thenReturn("user123");
    UserAuthentication userAuth = mock();
    when(userAuth.user()).thenReturn(user);
    AccessControl accessControl = new AccessControl(() -> userAuth, this.webAuthnProvider);

    boolean result = accessControl.isSetPasswordAllowed("user123");

    assertTrue(result, "Should be allowed for authenticated user");
  }

  @Test
  void testIsSetPasswordAllowedWithFullAccess() {
    when(this.authentication.hasFullAccess()).thenReturn(true);
    when(webAuthnProvider.getUserIdById("cred123")).thenReturn(null);

    boolean result = accessControl.isSetPasswordAllowed("user123");

    assertTrue(result, "Should be allowed with full access");
  }

  @Test
  void testIsGetPrivateTokensAllowedAsAuthenticatedUser() {
    User user = mock();
    when(user.id()).thenReturn("user123");
    UserAuthentication userAuth = mock();
    when(userAuth.user()).thenReturn(user);
    AccessControl accessControl = new AccessControl(() -> userAuth, this.webAuthnProvider);

    boolean result = accessControl.isGetPrivateTokensAllowed("user123");

    assertTrue(result, "Should be allowed for authenticated user");
  }

  @Test
  void testIsGetPrivateTokensAllowedWithFullAccess() {
    when(this.authentication.hasFullAccess()).thenReturn(true);

    boolean result = accessControl.isGetPrivateTokensAllowed("user123");

    assertTrue(result, "Should be allowed with full access");
  }

  @Test
  void testIsGetPrivateTokensAllowedForDifferentUserWithoutFullAccess() {
    User user = mock();
    when(user.id()).thenReturn("user123");
    UserAuthentication userAuth = mock();
    when(userAuth.user()).thenReturn(user);
    when(userAuth.hasFullAccess()).thenReturn(false);
    AccessControl accessControl = new AccessControl(() -> userAuth, this.webAuthnProvider);

    boolean result = accessControl.isGetPrivateTokensAllowed("user456");

    assertFalse(result, "Should not be allowed for different user without full access");
  }

  @Test
  void testIsGetServiceTokensAllowedWithFullAccess() {
    when(this.authentication.hasFullAccess()).thenReturn(true);

    boolean result = accessControl.isGetServiceTokensAllowed();

    assertTrue(result, "Should be allowed with full access");
  }

  @Test
  void testIsGetServiceTokensAllowedWithoutFullAccess() {
    when(this.authentication.hasFullAccess()).thenReturn(false);

    boolean result = accessControl.isGetServiceTokensAllowed();

    assertFalse(result, "Should not be allowed without full access");
  }

  @Test
  void testIsGetImpersonationTokensAllowedWithFullAccess() {
    when(this.authentication.hasFullAccess()).thenReturn(true);

    boolean result = accessControl.isGetImpersonationTokensAllowed();

    assertTrue(result, "Should be allowed with full access");
  }

  @Test
  void testIsGetImpersonationTokensAllowedWithoutFullAccess() {
    when(this.authentication.hasFullAccess()).thenReturn(false);

    boolean result = accessControl.isGetImpersonationTokensAllowed();

    assertFalse(result, "Should not be allowed without full access");
  }

  @Test
  void testIsAuthenticatedUserWithMatchingUserId() {
    User user = mock();
    when(user.id()).thenReturn("user123");
    UserAuthentication userAuth = mock();
    when(userAuth.user()).thenReturn(user);
    AccessControl accessControl = new AccessControl(() -> userAuth, this.webAuthnProvider);

    boolean result = accessControl.isAuthenticatedUser("user123");

    assertTrue(result, "Should be true for matching user ID");
  }

  @Test
  void testIsAuthenticatedUserWithDifferentUserId() {
    User user = mock();
    when(user.id()).thenReturn("user123");
    UserAuthentication userAuth = mock();
    when(userAuth.user()).thenReturn(user);
    AccessControl accessControl = new AccessControl(() -> userAuth, this.webAuthnProvider);

    boolean result = accessControl.isAuthenticatedUser("user456");

    assertFalse(result, "Should be false for different user ID");
  }

  @Test
  void testIsAuthenticatedUserWithNonUserAuthentication() {

    boolean result = accessControl.isAuthenticatedUser("user123");

    assertFalse(result, "Should be false for non-UserAuthentication");
  }
}

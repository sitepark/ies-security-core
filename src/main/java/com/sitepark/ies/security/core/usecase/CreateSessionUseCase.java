package com.sitepark.ies.security.core.usecase;

import com.sitepark.ies.security.core.domain.entity.AuthenticatedUser;
import com.sitepark.ies.security.core.domain.entity.Session;
import com.sitepark.ies.security.core.domain.entity.UserBasedAuthentication;
import com.sitepark.ies.security.core.port.PermissionLoader;
import com.sitepark.ies.security.core.port.SessionRegistry;
import com.sitepark.ies.sharedkernel.security.Permission;
import jakarta.inject.Inject;
import java.util.List;

public class CreateSessionUseCase {

  private final SessionRegistry sessionRegistry;

  private final PermissionLoader permissionLoader;

  @Inject
  protected CreateSessionUseCase(
      SessionRegistry sessionRegistry, PermissionLoader permissionLoader) {
    this.sessionRegistry = sessionRegistry;
    this.permissionLoader = permissionLoader;
  }

  public String createSession(AuthenticatedUser user, String purpose) {

    List<Permission> permissions = this.permissionLoader.loadByUser(user.getId());

    UserBasedAuthentication authentication =
        new UserBasedAuthentication(user.toBuilder().build(), permissions, purpose);

    Session session = this.sessionRegistry.create(authentication);
    return session.getId();
  }
}

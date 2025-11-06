package com.sitepark.ies.security.core.usecase.session;

import com.sitepark.ies.security.core.domain.entity.Session;
import com.sitepark.ies.security.core.port.PermissionLoader;
import com.sitepark.ies.security.core.port.SessionRegistry;
import com.sitepark.ies.sharedkernel.security.Permission;
import com.sitepark.ies.sharedkernel.security.User;
import com.sitepark.ies.sharedkernel.security.UserBasedAuthentication;
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

  public String createSession(User user, String purpose) {

    List<Permission> permissions = this.permissionLoader.loadByUser(user.id());

    UserBasedAuthentication authentication =
        UserBasedAuthentication.builder()
            .user(user.toBuilder().build())
            .permissions(permissions)
            .purpose(purpose)
            .build();

    Session session = this.sessionRegistry.create(authentication);
    return session.id();
  }
}

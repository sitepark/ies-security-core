package com.sitepark.ies.security.core.port;

import com.sitepark.ies.sharedkernel.security.Permission;
import java.util.List;

@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface PermissionLoader {
  List<Permission> loadByUser(String id);
}

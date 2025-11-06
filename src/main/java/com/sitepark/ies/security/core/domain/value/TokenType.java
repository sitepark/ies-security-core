package com.sitepark.ies.security.core.domain.value;

public enum TokenType {
  /** Token for personal use. */
  PRIVATE,
  /** Token for impersonation purposes. */
  IMPERSONATION,
  /** Token for external service communication. */
  SERVICE
}

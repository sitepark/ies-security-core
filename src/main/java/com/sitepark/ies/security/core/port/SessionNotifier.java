package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.entity.Session;

/**
 * Tells the rest of the application about sessions that end, so that it can release what it keeps
 * per session or per user (locks, temporary files, open connections). The {@link SessionRegistry}
 * calls it whenever a session ends: on logout and on timeout.
 */
@FunctionalInterface
public interface SessionNotifier {

  /**
   * Called after a session has ended.
   *
   * @param session the session that ended
   */
  void notifyClosed(Session session);
}

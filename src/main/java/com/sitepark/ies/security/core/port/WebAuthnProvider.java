package com.sitepark.ies.security.core.port;

import com.sitepark.ies.security.core.domain.entity.WebAuthnRegisteredCredential;
import com.sitepark.ies.security.core.domain.value.WebAuthnAssertionFinishResult;
import com.sitepark.ies.sharedkernel.security.User;
import java.net.URI;
import java.util.List;

public interface WebAuthnProvider {
  String startRegistration(User user, URI origin, String applicationName, String passkeyName);

  void finishRegistration(String publicKeyCredentialJson);

  String startAssertion(URI origin, String applicationName);

  WebAuthnAssertionFinishResult finishAssertion(String publicKeyCredentialJson);

  List<WebAuthnRegisteredCredential> findRegisteredCredentialByUserId(String userId);

  void removeRegisteredCredential(String id);

  String getUserIdById(String id);
}

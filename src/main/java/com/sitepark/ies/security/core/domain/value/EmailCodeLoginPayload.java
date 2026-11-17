package com.sitepark.ies.security.core.domain.value;

import com.sitepark.ies.sharedkernel.security.CodeVerificationPayload;

/** The challenge of a login that waits for the e-mail code of the user. */
public record EmailCodeLoginPayload(String userId) implements CodeVerificationPayload {}

package com.sitepark.ies.security.core.domain.value;

import com.sitepark.ies.sharedkernel.security.CodeVerificationPayload;

/** The challenge that confirms the e-mail address a user wants to receive login codes at. */
public record EmailCodeSetupPayload(String userId, String address)
    implements CodeVerificationPayload {}

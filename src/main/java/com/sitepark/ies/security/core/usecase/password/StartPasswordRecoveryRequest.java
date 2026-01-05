package com.sitepark.ies.security.core.usecase.password;

import com.sitepark.ies.sharedkernel.email.ExternalEmailParameters;

public record StartPasswordRecoveryRequest(
    String username, ExternalEmailParameters emailParameters) {}

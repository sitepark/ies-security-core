package com.sitepark.ies.security.core.usecase.password;

import com.sitepark.ies.sharedkernel.email.ExternalEmailParameters;

public record FinishPasswordRecoveryRequest(
    String challengeId, int code, String newPassword, ExternalEmailParameters emailParameters) {}

package com.sitepark.ies.security.core.usecase.password;

import com.sitepark.ies.sharedkernel.security.CodeVerificationPayload;

public record PasswordRecoverPayload(String username) implements CodeVerificationPayload {}

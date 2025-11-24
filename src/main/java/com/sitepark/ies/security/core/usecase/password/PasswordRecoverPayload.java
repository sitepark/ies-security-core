package com.sitepark.ies.security.core.usecase.password;

import com.sitepark.ies.security.core.domain.value.CodeVerificationPayload;

public record PasswordRecoverPayload(String username) implements CodeVerificationPayload {}

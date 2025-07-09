package com.sitepark.ies.security.core.domain.value;

public record WebAuthnAssertionFinishResult(
    boolean success, boolean userVerified, String applicationName, String username) {}

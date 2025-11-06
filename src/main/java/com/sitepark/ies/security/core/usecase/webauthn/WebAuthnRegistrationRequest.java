package com.sitepark.ies.security.core.usecase.webauthn;

public record WebAuthnRegistrationRequest(
    String userId, String origin, String applicationName, String keyName) {}

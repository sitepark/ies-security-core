package com.sitepark.ies.security.core.usecase.webauthn;

public record WebAuthnRegistrationCommand(
    String userId, String origin, String applicationName, String keyName) {}

package com.sitepark.ies.security.core.usecase.webauthn;

public record WebAuthnAssertionRequest(String origin, String applicationName) {}

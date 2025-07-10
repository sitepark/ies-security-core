package com.sitepark.ies.security.core.usecase.webauthn;

public record WebAuthnAssertionCommand(String origin, String applicationName) {}

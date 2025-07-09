package com.sitepark.ies.security.core.usecase.authentication;

public record WebAuthnAssertionCommand(String origin, String applicationName) {}

package com.sitepark.ies.security.core.usecase.authentication;

public record WebAuthnRegistrationCommand(
    String userId, String origin, String applicationName, String keyName) {}

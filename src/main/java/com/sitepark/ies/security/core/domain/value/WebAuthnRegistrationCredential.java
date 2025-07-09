package com.sitepark.ies.security.core.domain.value;

public record WebAuthnRegistrationCredential(String publicKeyCredentialJson, String userId) {}

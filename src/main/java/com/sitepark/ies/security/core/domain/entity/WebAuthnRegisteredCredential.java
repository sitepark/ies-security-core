package com.sitepark.ies.security.core.domain.entity;

import java.time.Instant;

public record WebAuthnRegisteredCredential(String id, String name, Instant createdAt) {}

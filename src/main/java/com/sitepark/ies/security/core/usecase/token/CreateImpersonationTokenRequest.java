package com.sitepark.ies.security.core.usecase.token;

import java.time.Instant;
import org.jetbrains.annotations.Nullable;

public record CreateImpersonationTokenRequest(
    String userId, String name, @Nullable Instant expiresAt) {}

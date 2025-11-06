package com.sitepark.ies.security.core.usecase.token;

import com.sitepark.ies.security.core.domain.entity.AccessToken;

public record CreateImpersonationTokenResult(AccessToken entity, String token) {}

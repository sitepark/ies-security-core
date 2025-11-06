package com.sitepark.ies.security.core.usecase.token;

import com.sitepark.ies.security.core.domain.entity.AccessToken;

public record CreateTokenResult(AccessToken entity, String token) {}

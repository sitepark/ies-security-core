package com.sitepark.ies.security.core.domain.value;

public record OAuth2User(
    String id, String name, String givenName, String familyName, String email) {}

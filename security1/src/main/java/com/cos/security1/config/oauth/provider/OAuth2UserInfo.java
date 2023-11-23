package com.cos.security1.config.oauth.provider;

public interface OAuth2UserInfo {
    String getProviderId();
    String getProider();
    String getEmail();
    String getName();
}

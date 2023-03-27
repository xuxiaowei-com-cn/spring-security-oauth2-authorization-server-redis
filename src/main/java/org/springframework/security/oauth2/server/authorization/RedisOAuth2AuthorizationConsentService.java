package org.springframework.security.oauth2.server.authorization;

import lombok.extern.slf4j.Slf4j;

/**
 * 一个 Redis 的 {@link OAuth2AuthorizationConsentService} 实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see InMemoryOAuth2AuthorizationConsentService
 * @see JdbcOAuth2AuthorizationConsentService
 */
@Slf4j
public class RedisOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

	@Override
	public void save(OAuth2AuthorizationConsent authorizationConsent) {

	}

	@Override
	public void remove(OAuth2AuthorizationConsent authorizationConsent) {

	}

	@Override
	public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
		return null;
	}

}

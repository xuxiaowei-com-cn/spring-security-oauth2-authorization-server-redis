package cn.com.xuxiaowei.boot.oauth2.service;

import cn.com.xuxiaowei.boot.oauth2.properties.SpringAuthorizationServerRedisProperties;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * @author xuxiaowei
 * @since 2.0.0
 */
public class RedisOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

	private final JdbcOAuth2AuthorizationConsentService jdbcOAuth2AuthorizationConsentService;

	private final StringRedisTemplate stringRedisTemplate;

	private final SpringAuthorizationServerRedisProperties properties;

	public RedisOAuth2AuthorizationConsentService(JdbcOperations jdbcOperations,
			RegisteredClientRepository registeredClientRepository, StringRedisTemplate stringRedisTemplate,
			SpringAuthorizationServerRedisProperties properties) {
		this.jdbcOAuth2AuthorizationConsentService = new JdbcOAuth2AuthorizationConsentService(jdbcOperations,
				registeredClientRepository);
		this.stringRedisTemplate = stringRedisTemplate;
		this.properties = properties;
	}

	@Override
	public void save(OAuth2AuthorizationConsent authorizationConsent) {
		jdbcOAuth2AuthorizationConsentService.save(authorizationConsent);
	}

	@Override
	public void remove(OAuth2AuthorizationConsent authorizationConsent) {
		jdbcOAuth2AuthorizationConsentService.remove(authorizationConsent);
	}

	@Override
	public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
		return jdbcOAuth2AuthorizationConsentService.findById(registeredClientId, principalName);
	}

}

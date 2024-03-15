package cn.com.xuxiaowei.boot.oauth2.service;

import cn.com.xuxiaowei.boot.oauth2.properties.SpringAuthorizationServerRedisProperties;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * @author xuxiaowei
 * @since 2.0.0
 */
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

	private final JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService;

	private final StringRedisTemplate stringRedisTemplate;

	private final SpringAuthorizationServerRedisProperties properties;

	public RedisOAuth2AuthorizationService(JdbcOperations jdbcOperations,
			RegisteredClientRepository registeredClientRepository, StringRedisTemplate stringRedisTemplate,
			SpringAuthorizationServerRedisProperties properties) {
		this.jdbcOAuth2AuthorizationService = new JdbcOAuth2AuthorizationService(jdbcOperations,
				registeredClientRepository);
		this.stringRedisTemplate = stringRedisTemplate;
		this.properties = properties;
	}

	public RedisOAuth2AuthorizationService(JdbcOperations jdbcOperations,
			RegisteredClientRepository registeredClientRepository, StringRedisTemplate stringRedisTemplate,
			SpringAuthorizationServerRedisProperties properties, LobHandler lobHandler) {
		this.jdbcOAuth2AuthorizationService = new JdbcOAuth2AuthorizationService(jdbcOperations,
				registeredClientRepository, lobHandler);
		this.stringRedisTemplate = stringRedisTemplate;
		this.properties = properties;
	}

	@Override
	public void save(OAuth2Authorization authorization) {
		jdbcOAuth2AuthorizationService.save(authorization);
	}

	@Override
	public void remove(OAuth2Authorization authorization) {
		jdbcOAuth2AuthorizationService.remove(authorization);
	}

	@Override
	public OAuth2Authorization findById(String id) {
		return jdbcOAuth2AuthorizationService.findById(id);
	}

	@Override
	public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
		return jdbcOAuth2AuthorizationService.findByToken(token, tokenType);
	}

}

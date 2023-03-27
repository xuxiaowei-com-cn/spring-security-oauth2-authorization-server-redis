package org.springframework.security.oauth2.server.authorization;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;

import javax.sql.DataSource;
import java.util.concurrent.TimeUnit;

/**
 * 一个 Redis 的 {@link OAuth2AuthorizationService} 实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see InMemoryOAuth2AuthorizationService
 * @see JdbcOAuth2AuthorizationService
 */
@Slf4j
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

	/**
	 *
	 */
	public static final String OAUTH2_AUTHORIZATION_ID = "oauth2_authorization:id:";

	/**
	 *
	 */
	public static final String OAUTH2_AUTHORIZATION_TOKEN_TYPE = "oauth2_authorization:tokenType:";

	private RedisTemplate<String, OAuth2Authorization> redisTemplate;

	private JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService;

	@Autowired
	public void setRedisTemplate(
			@Qualifier(RedisOAuth2AuthorizationServiceConfiguration.REDIS_TEMPLATE_BEAN_NAME) RedisTemplate<String, OAuth2Authorization> redisTemplate) {
		this.redisTemplate = redisTemplate;
	}

	@Autowired
	public void setJdbcOAuth2AuthorizationService(DataSource dataSource) {
		JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
		JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(
				jdbcTemplate);
		this.jdbcOAuth2AuthorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate,
				jdbcRegisteredClientRepository);
	}

	@Override
	public void save(OAuth2Authorization authorization) {

	}

	@Override
	public void remove(OAuth2Authorization authorization) {

	}

	@Override
	public OAuth2Authorization findById(String id) {
		OAuth2Authorization oauth2AuthorizationRedis = redisTemplate.opsForValue().get(OAUTH2_AUTHORIZATION_ID + id);

		OAuth2Authorization oauth2AuthorizationResult;
		OAuth2Authorization oauth2AuthorizationByDatabase;

		if (oauth2AuthorizationRedis == null) {
			oauth2AuthorizationByDatabase = jdbcOAuth2AuthorizationService.findById(id);
			log.debug("根据 id：{} 直接查询数据库中的授权：{}", id, oauth2AuthorizationByDatabase);

			if (oauth2AuthorizationByDatabase != null) {
				set(oauth2AuthorizationByDatabase, 60, TimeUnit.MINUTES);
			}

			oauth2AuthorizationResult = oauth2AuthorizationByDatabase;
		}
		else {
			log.debug("根据 id：{} 直接查询Redis中的授权：{}", id, oauth2AuthorizationRedis);
			oauth2AuthorizationResult = oauth2AuthorizationRedis;
		}

		return oauth2AuthorizationResult;
	}

	@Override
	public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {

		assert tokenType != null;
		String tokenTypeValue = tokenType.getValue();

		// @formatter:off
		OAuth2Authorization oauth2Authorization = redisTemplate.opsForValue().get(OAUTH2_AUTHORIZATION_TOKEN_TYPE + tokenTypeValue + ":" + token);
		// @formatter:on

		return null;
	}

	public void set(@NonNull OAuth2Authorization oauth2Authorization, long timeout, TimeUnit unit) {
		// @formatter:off
		redisTemplate.opsForValue().set(OAUTH2_AUTHORIZATION_ID + oauth2Authorization.getId(), oauth2Authorization, timeout, unit);
		redisTemplate.opsForValue().set(OAUTH2_AUTHORIZATION_TOKEN_TYPE + oauth2Authorization.getAccessToken().getToken().getTokenValue(), oauth2Authorization, timeout, unit);
		// @formatter:on
	}

}

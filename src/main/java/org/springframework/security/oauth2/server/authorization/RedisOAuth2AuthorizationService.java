package org.springframework.security.oauth2.server.authorization;

/*-
 * #%L
 * spring-security-oauth2-authorization-server-redis
 * %%
 * Copyright (C) 2022 - 2023 徐晓伟工作室
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.properties.SpringAuthorizationServerRedisProperties;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.util.concurrent.TimeUnit;

import static org.springframework.security.oauth2.server.authorization.configuration.RedisSpringAuthorizationServerConfiguration.REDIS_TEMPLATE_OAUTH2_AUTHORIZATION_BEAN_NAME;

/**
 * 一个 Redis 的 {@link OAuth2AuthorizationService} 实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see InMemoryOAuth2AuthorizationService
 * @see JdbcOAuth2AuthorizationService
 */
@Slf4j
@Service
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

	/**
	 * 根据 id 查询时放入Redis中的部分 key
	 */
	public static final String OAUTH2_AUTHORIZATION_ID = ":oauth2_authorization:id:";

	/**
	 * 根据 token类型、token 查询时放入Redis中的部分 key
	 */
	public static final String OAUTH2_AUTHORIZATION_TOKEN_TYPE = ":oauth2_authorization:tokenType:";

	private RedisTemplate<String, OAuth2Authorization> redisTemplate;

	private JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService;

	private SpringAuthorizationServerRedisProperties springAuthorizationServerRedisProperties;

	@Autowired
	// @formatter:off
	public void setRedisTemplate(@Qualifier(REDIS_TEMPLATE_OAUTH2_AUTHORIZATION_BEAN_NAME) RedisTemplate<String, OAuth2Authorization> redisTemplate) {
		this.redisTemplate = redisTemplate;
	}
	// @formatter:on

	@Autowired
	public void setJdbcOAuth2AuthorizationService(DataSource dataSource) {
		JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
		// @formatter:off
		JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		this.jdbcOAuth2AuthorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, jdbcRegisteredClientRepository);
		// @formatter:on
	}

	@Autowired
	public void setSpringAuthorizationServerRedisProperties(
			SpringAuthorizationServerRedisProperties springAuthorizationServerRedisProperties) {
		this.springAuthorizationServerRedisProperties = springAuthorizationServerRedisProperties;
	}

	@Override
	public void save(OAuth2Authorization authorization) {
		if (authorization != null) {

			long authorizationTimeout = springAuthorizationServerRedisProperties.getAuthorizationTimeout();

			set(authorization, authorizationTimeout, TimeUnit.SECONDS);

			jdbcOAuth2AuthorizationService.save(authorization);
		}
	}

	@Override
	public void remove(OAuth2Authorization authorization) {
		if (authorization != null) {

			String prefix = springAuthorizationServerRedisProperties.getPrefix();

			redisTemplate.delete(prefix + OAUTH2_AUTHORIZATION_ID + authorization.getId());

			OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
			if (accessToken != null) {
				OAuth2AccessToken token = accessToken.getToken();
				if (token != null) {
					String tokenType = token.getTokenType().getValue();
					String tokenValue = token.getTokenValue();
					redisTemplate.delete(prefix + OAUTH2_AUTHORIZATION_TOKEN_TYPE + tokenType + ":" + tokenValue);
				}
			}

			jdbcOAuth2AuthorizationService.remove(authorization);
		}
	}

	@Override
	public OAuth2Authorization findById(String id) {

		String prefix = springAuthorizationServerRedisProperties.getPrefix();

		// @formatter:off
		OAuth2Authorization oauth2AuthorizationRedis = redisTemplate.opsForValue().get(prefix + OAUTH2_AUTHORIZATION_ID + id);
		// @formatter:on

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

		String prefix = springAuthorizationServerRedisProperties.getPrefix();

		assert tokenType != null;
		String tokenTypeValue = tokenType.getValue();

		// @formatter:off
		OAuth2Authorization oauth2AuthorizationByRedis = redisTemplate.opsForValue().get(prefix + OAUTH2_AUTHORIZATION_TOKEN_TYPE + tokenTypeValue + ":" + token);
		// @formatter:on

		OAuth2Authorization oauth2AuthorizationResult;
		OAuth2Authorization oauth2AuthorizationByDatabase;

		if (oauth2AuthorizationByRedis == null) {
			oauth2AuthorizationByDatabase = jdbcOAuth2AuthorizationService.findByToken(token, tokenType);
			log.debug("根据 token：{}、tokenType：{} 直接查询数据库中的客户：{}", token, tokenType, oauth2AuthorizationByDatabase);

			if (oauth2AuthorizationByDatabase != null) {

				long authorizationTimeout = springAuthorizationServerRedisProperties.getAuthorizationTimeout();

				set(oauth2AuthorizationByDatabase, authorizationTimeout, TimeUnit.SECONDS);
			}

			oauth2AuthorizationResult = oauth2AuthorizationByDatabase;
		}
		else {
			log.debug("根据 token：{}、tokenType：{} 直接查询Redis中的客户：{}", token, tokenType, oauth2AuthorizationByRedis);
			oauth2AuthorizationResult = oauth2AuthorizationByRedis;
		}

		return oauth2AuthorizationResult;
	}

	public void set(@NonNull OAuth2Authorization authorization, long timeout, TimeUnit unit) {

		String prefix = springAuthorizationServerRedisProperties.getPrefix();

		// @formatter:off
		redisTemplate.opsForValue().set(prefix + OAUTH2_AUTHORIZATION_ID + authorization.getId(), authorization, timeout, unit);
		// @formatter:on

		OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
		if (accessToken != null) {
			OAuth2AccessToken token = accessToken.getToken();
			if (token != null) {
				String tokenValue = token.getTokenValue();
				redisTemplate.opsForValue()
					.set(prefix + OAUTH2_AUTHORIZATION_TOKEN_TYPE + OAuth2TokenType.ACCESS_TOKEN.getValue() + ":"
							+ tokenValue, authorization, timeout, unit);
			}
		}

		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
		if (refreshToken != null) {
			OAuth2RefreshToken token = refreshToken.getToken();
			if (token != null) {
				String tokenValue = token.getTokenValue();
				redisTemplate.opsForValue()
					.set(prefix + OAUTH2_AUTHORIZATION_TOKEN_TYPE + OAuth2TokenType.REFRESH_TOKEN.getValue() + ":"
							+ tokenValue, authorization, timeout, unit);
			}
		}

	}

}

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
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.properties.SpringAuthorizationServerRedisProperties;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.util.concurrent.TimeUnit;

import static org.springframework.security.oauth2.server.authorization.configuration.RedisSpringAuthorizationServerConfiguration.REDIS_TEMPLATE_OAUTH2_AUTHORIZATION_CONSENT_BEAN_NAME;

/**
 * 一个 Redis 的 {@link OAuth2AuthorizationConsentService} 实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see InMemoryOAuth2AuthorizationConsentService
 * @see JdbcOAuth2AuthorizationConsentService
 */
@Slf4j
@Service
public class RedisOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

	/**
	 * 查询时放入Redis中的部分 key
	 */
	public static final String OAUTH2_AUTHORIZATION_CONSENT = ":oauth2_authorization_consent:";

	private RedisTemplate<String, OAuth2AuthorizationConsent> redisTemplate;

	private JdbcOAuth2AuthorizationConsentService jdbcOAuth2AuthorizationConsentService;

	private SpringAuthorizationServerRedisProperties springAuthorizationServerRedisProperties;

	@Autowired
	public void setSpringAuthorizationServerRedisProperties(
			SpringAuthorizationServerRedisProperties springAuthorizationServerRedisProperties) {
		this.springAuthorizationServerRedisProperties = springAuthorizationServerRedisProperties;
	}

	@Autowired
	// @formatter:off
	public void setRedisTemplate(@Qualifier(REDIS_TEMPLATE_OAUTH2_AUTHORIZATION_CONSENT_BEAN_NAME) RedisTemplate<String, OAuth2AuthorizationConsent> redisTemplate) {
		this.redisTemplate = redisTemplate;
	}
	// @formatter:on

	@Autowired
	public void setJdbcOAuth2AuthorizationConsentService(DataSource dataSource) {
		JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
		// @formatter:off
		JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		this.jdbcOAuth2AuthorizationConsentService = new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, jdbcRegisteredClientRepository);
		// @formatter:on
	}

	@Override
	public void save(OAuth2AuthorizationConsent authorizationConsent) {
		if (authorizationConsent != null) {

			long authorizationConsentTimeout = springAuthorizationServerRedisProperties
				.getAuthorizationConsentTimeout();

			set(authorizationConsent, authorizationConsentTimeout, TimeUnit.SECONDS);

			jdbcOAuth2AuthorizationConsentService.save(authorizationConsent);
		}
	}

	@Override
	public void remove(OAuth2AuthorizationConsent authorizationConsent) {
		if (authorizationConsent != null) {

			String prefix = springAuthorizationServerRedisProperties.getPrefix();

			String registeredClientId = authorizationConsent.getRegisteredClientId();
			String principalName = authorizationConsent.getPrincipalName();

			redisTemplate.delete(prefix + OAUTH2_AUTHORIZATION_CONSENT + registeredClientId + ":" + principalName);

			jdbcOAuth2AuthorizationConsentService.remove(authorizationConsent);
		}
	}

	@Override
	public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
		String prefix = springAuthorizationServerRedisProperties.getPrefix();
		long authorizationTimeout = springAuthorizationServerRedisProperties.getAuthorizationTimeout();

		// @formatter:off
		OAuth2AuthorizationConsent oauth2AuthorizationConsentRedis = redisTemplate.opsForValue().get(prefix + OAUTH2_AUTHORIZATION_CONSENT + registeredClientId  + ":"+ principalName);
		// @formatter:on

		OAuth2AuthorizationConsent oauth2AuthorizationResult;
		OAuth2AuthorizationConsent oauth2AuthorizationByDatabase;

		if (oauth2AuthorizationConsentRedis == null) {
			oauth2AuthorizationByDatabase = jdbcOAuth2AuthorizationConsentService.findById(registeredClientId,
					principalName);
			log.debug("根据 registeredClientId：{}、principalName：{} 直接查询数据库中的授权：{}", registeredClientId, principalName,
					oauth2AuthorizationByDatabase);

			if (oauth2AuthorizationByDatabase != null) {
				set(oauth2AuthorizationByDatabase, authorizationTimeout, TimeUnit.SECONDS);
			}

			oauth2AuthorizationResult = oauth2AuthorizationByDatabase;
		}
		else {
			log.debug("根据 registeredClientId：{}、principalName：{} 直接查询Redis中的授权：{}", registeredClientId, principalName,
					oauth2AuthorizationConsentRedis);
			oauth2AuthorizationResult = oauth2AuthorizationConsentRedis;
		}

		return oauth2AuthorizationResult;
	}

	public void set(@NonNull OAuth2AuthorizationConsent authorizationConsent, long timeout, TimeUnit unit) {

		String prefix = springAuthorizationServerRedisProperties.getPrefix();

		String registeredClientId = authorizationConsent.getRegisteredClientId();
		String principalName = authorizationConsent.getPrincipalName();

		// @formatter:off
		redisTemplate.opsForValue().set(prefix + OAUTH2_AUTHORIZATION_CONSENT + registeredClientId + ":"+ principalName , authorizationConsent, timeout, unit);
		// @formatter:on
	}

}

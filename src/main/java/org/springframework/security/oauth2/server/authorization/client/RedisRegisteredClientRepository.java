package org.springframework.security.oauth2.server.authorization.client;

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

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.NonNull;
import org.springframework.security.oauth2.server.authorization.properties.SpringAuthorizationServerRedisProperties;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.util.concurrent.TimeUnit;

import static org.springframework.security.oauth2.server.authorization.configuration.RedisSpringAuthorizationServerConfiguration.REDIS_TEMPLATE_REGISTERED_CLIENT_BEAN_NAME;

/**
 * 一个 Redis 的 {@link RegisteredClientRepository} 实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see InMemoryRegisteredClientRepository
 * @see JdbcRegisteredClientRepository
 */
@Slf4j
@Service
public class RedisRegisteredClientRepository implements RegisteredClientRepository {

	/**
	 * 根据 id 查询时放入Redis中的部分 key
	 */
	public static final String REGISTERED_CLIENT_ID = ":registered_client:id:";

	/**
	 * 根据 clientId 查询时放入Redis中的部分 key
	 */
	public static final String REGISTERED_CLIENT_CLIENT_ID = ":registered_client:clientId:";

	private RedisTemplate<String, RegisteredClient> redisTemplate;

	private JdbcRegisteredClientRepository jdbcRegisteredClientRepository;

	private SpringAuthorizationServerRedisProperties springAuthorizationServerRedisProperties;

	@Autowired
	// @formatter:off
	public void setRedisTemplate(@Qualifier(REDIS_TEMPLATE_REGISTERED_CLIENT_BEAN_NAME) RedisTemplate<String, RegisteredClient> redisTemplate) {
		this.redisTemplate = redisTemplate;
	}
	// @formatter:on

	@Autowired
	public void setJdbcRegisteredClientRepository(DataSource dataSource) {
		JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
		this.jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
	}

	@Autowired
	// @formatter:off
	public void setSpringAuthorizationServerRedisProperties(SpringAuthorizationServerRedisProperties springAuthorizationServerRedisProperties) {
		this.springAuthorizationServerRedisProperties = springAuthorizationServerRedisProperties;
	}
	// @formatter:on

	@Override
	public void save(RegisteredClient registeredClient) {
		if (registeredClient != null) {

			long registeredClientTimeout = springAuthorizationServerRedisProperties.getRegisteredClientTimeout();

			set(registeredClient, registeredClientTimeout, TimeUnit.SECONDS);

			jdbcRegisteredClientRepository.save(registeredClient);
		}
	}

	@Override
	public RegisteredClient findById(String id) {

		String prefix = springAuthorizationServerRedisProperties.getPrefix();

		RegisteredClient registeredClientByRedis = redisTemplate.opsForValue().get(prefix + REGISTERED_CLIENT_ID + id);

		RegisteredClient registeredClientResult;
		RegisteredClient registeredClientByDatabase;

		if (registeredClientByRedis == null) {
			registeredClientByDatabase = jdbcRegisteredClientRepository.findById(id);
			log.debug("根据 id：{} 直接查询数据库中的客户：{}", id, registeredClientByDatabase);

			if (registeredClientByDatabase != null) {

				long registeredClientTimeout = springAuthorizationServerRedisProperties.getRegisteredClientTimeout();

				set(registeredClientByDatabase, registeredClientTimeout, TimeUnit.SECONDS);
			}

			registeredClientResult = registeredClientByDatabase;
		}
		else {
			log.debug("根据 id：{} 直接查询Redis中的客户：{}", id, registeredClientByRedis);
			registeredClientResult = registeredClientByRedis;
		}

		return registeredClientResult;
	}

	@Override
	public RegisteredClient findByClientId(String clientId) {

		String prefix = springAuthorizationServerRedisProperties.getPrefix();

		// @formatter:off
		RegisteredClient registeredClientByRedis = redisTemplate.opsForValue().get(prefix + REGISTERED_CLIENT_CLIENT_ID + clientId);
		// @formatter:on

		RegisteredClient registeredClientResult;
		RegisteredClient registeredClientByDatabase;

		if (registeredClientByRedis == null) {
			registeredClientByDatabase = jdbcRegisteredClientRepository.findByClientId(clientId);
			log.debug("根据 clientId：{} 直接查询数据库中的客户：{}", clientId, registeredClientByDatabase);

			if (registeredClientByDatabase != null) {

				long registeredClientTimeout = springAuthorizationServerRedisProperties.getRegisteredClientTimeout();

				set(registeredClientByDatabase, registeredClientTimeout, TimeUnit.SECONDS);
			}

			registeredClientResult = registeredClientByDatabase;
		}
		else {
			log.debug("根据 clientId：{} 直接查询Redis中的客户：{}", clientId, registeredClientByRedis);
			registeredClientResult = registeredClientByRedis;
		}

		return registeredClientResult;
	}

	public void set(@NonNull RegisteredClient registeredClient, long timeout, TimeUnit unit) {
		String prefix = springAuthorizationServerRedisProperties.getPrefix();

		// @formatter:off
		redisTemplate.opsForValue().set(prefix + REGISTERED_CLIENT_ID + registeredClient.getId(), registeredClient, timeout, unit);
		redisTemplate.opsForValue().set(prefix + REGISTERED_CLIENT_CLIENT_ID + registeredClient.getClientId(), registeredClient, timeout, unit);
		// @formatter:on
	}

}

package org.springframework.security.oauth2.server.authorization.configuration;

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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.utils.ObjectMapperUtils;

/**
 * {@link OAuth2AuthorizationService} 配置
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Configuration
public class RedisSpringAuthorizationServerConfiguration {

	public static final String REDIS_TEMPLATE_REGISTERED_CLIENT_BEAN_NAME = "redisTemplateRegisteredClient";

	public static final String REDIS_TEMPLATE_OAUTH2_AUTHORIZATION_BEAN_NAME = "redisTemplateOAuth2Authorization";

	/**
	 * 注意：如果要使用注解 {@link Autowired} 管理 {@link RedisTemplate}， 则需要将 {@link RedisTemplate} 的
	 * {@link Bean} 缺省泛型
	 * @param redisConnectionFactory Redis 连接工厂
	 * @return 返回 Redis 模板
	 */
	@Bean(REDIS_TEMPLATE_REGISTERED_CLIENT_BEAN_NAME)
	@ConditionalOnMissingBean(name = REDIS_TEMPLATE_REGISTERED_CLIENT_BEAN_NAME)
	public RedisTemplate<String, RegisteredClient> redisTemplate(RedisConnectionFactory redisConnectionFactory) {

		// Helper类简化了 Redis 数据访问代码
		RedisTemplate<String, RegisteredClient> template = new RedisTemplate<>();

		// 设置连接工厂。
		template.setConnectionFactory(redisConnectionFactory);

		// 可以使用读写JSON
		Jackson2JsonRedisSerializer<RegisteredClient> jackson2JsonRedisSerializer = new Jackson2JsonRedisSerializer<>(
				RegisteredClient.class);

		jackson2JsonRedisSerializer.setObjectMapper(ObjectMapperUtils.redis());

		// Redis 字符串：键、值序列化
		template.setKeySerializer(new StringRedisSerializer());
		template.setValueSerializer(jackson2JsonRedisSerializer);

		// Redis Hash：键、值序列化
		template.setHashKeySerializer(new StringRedisSerializer());
		template.setHashValueSerializer(jackson2JsonRedisSerializer);

		template.afterPropertiesSet();

		return template;
	}

	/**
	 * 注意：如果要使用注解 {@link Autowired} 管理 {@link RedisTemplate}， 则需要将 {@link RedisTemplate} 的
	 * {@link Bean} 缺省泛型
	 * @param redisConnectionFactory Redis 连接工厂
	 * @return 返回 Redis 模板
	 */
	@Bean(REDIS_TEMPLATE_OAUTH2_AUTHORIZATION_BEAN_NAME)
	@ConditionalOnMissingBean(name = REDIS_TEMPLATE_OAUTH2_AUTHORIZATION_BEAN_NAME)
	public RedisTemplate<String, OAuth2Authorization> redisTemplate2(RedisConnectionFactory redisConnectionFactory) {

		// Helper类简化了 Redis 数据访问代码
		RedisTemplate<String, OAuth2Authorization> template = new RedisTemplate<>();

		// 设置连接工厂。
		template.setConnectionFactory(redisConnectionFactory);

		// 可以使用读写JSON
		Jackson2JsonRedisSerializer<OAuth2Authorization> jackson2JsonRedisSerializer = new Jackson2JsonRedisSerializer<>(
				OAuth2Authorization.class);

		jackson2JsonRedisSerializer.setObjectMapper(ObjectMapperUtils.redis());

		// Redis 字符串：键、值序列化
		template.setKeySerializer(new StringRedisSerializer());
		template.setValueSerializer(jackson2JsonRedisSerializer);

		// Redis Hash：键、值序列化
		template.setHashKeySerializer(new StringRedisSerializer());
		template.setHashValueSerializer(jackson2JsonRedisSerializer);

		template.afterPropertiesSet();

		return template;
	}

}

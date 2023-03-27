package org.springframework.security.oauth2.server.authorization.client;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.cache.RedisCacheWriter;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.oauth2.server.authorization.utils.ObjectMapperUtils;

import java.util.Objects;

/**
 * {@link RedisRegisteredClientRepository} 配置
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Configuration
public class RedisRegisteredClientRepositoryConfiguration {

	public static final String REDIS_CACHE_MANAGER_BEAN_NAME = "redisCacheManagerRedisRegisteredClientRepository";

	public static final String REDIS_TEMPLATE_BEAN_NAME = "redisTemplateRedisRegisteredClientRepository";

	/**
	 * Redis 缓存管理器
	 * @param redisTemplate Redis 模板
	 * @return 返回 Redis 缓存管理器
	 */
	@Bean(REDIS_CACHE_MANAGER_BEAN_NAME)
	@ConditionalOnMissingBean(name = REDIS_CACHE_MANAGER_BEAN_NAME)
	public RedisCacheManager redisCacheManagerRedisRegisteredClientRepository(
			@Qualifier(REDIS_TEMPLATE_BEAN_NAME) RedisTemplate<String, RegisteredClient> redisTemplate) {

		// 从 RedisTemplate 中获取连接
		RedisConnectionFactory connectionFactory = redisTemplate.getConnectionFactory();

		// 检查 RedisConnectionFactory 是否为 null
		RedisConnectionFactory redisConnectionFactory = Objects.requireNonNull(connectionFactory);

		// 检查 RedisConnectionFactory 是否为 null
		// 创建新的无锁 RedisCacheWriter
		RedisCacheWriter redisCacheWriter = RedisCacheWriter.nonLockingRedisCacheWriter(redisConnectionFactory);

		// 获取 RedisTemplate 的序列化
		RedisSerializer<?> valueSerializer = redisTemplate.getValueSerializer();

		// 序列化对
		RedisSerializationContext.SerializationPair<?> serializationPair = RedisSerializationContext.SerializationPair
			.fromSerializer(valueSerializer);

		// 获取默认缓存配置
		RedisCacheConfiguration redisCacheConfiguration = RedisCacheConfiguration.defaultCacheConfig();

		// 设置序列化
		RedisCacheConfiguration redisCacheConfigurationSerialize = redisCacheConfiguration
			.serializeValuesWith(serializationPair);

		// 创建并返回 Redis 缓存管理
		return new RedisCacheManager(redisCacheWriter, redisCacheConfigurationSerialize);
	}

	/**
	 * 注意：如果要使用注解 {@link Autowired} 管理 {@link RedisTemplate}， 则需要将 {@link RedisTemplate} 的
	 * {@link Bean} 缺省泛型
	 * @param redisConnectionFactory Redis 连接工厂
	 * @return 返回 Redis 模板
	 */
	@Bean(REDIS_TEMPLATE_BEAN_NAME)
	@ConditionalOnMissingBean(name = REDIS_TEMPLATE_BEAN_NAME)
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

}

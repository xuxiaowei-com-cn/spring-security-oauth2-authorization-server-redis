package cn.com.xuxiaowei.boot.oauth2.annotation;

import cn.com.xuxiaowei.boot.oauth2.properties.SpringAuthorizationServerRedisProperties;
import cn.com.xuxiaowei.boot.oauth2.service.RedisOAuth2AuthorizationConsentService;
import cn.com.xuxiaowei.boot.oauth2.service.RedisOAuth2AuthorizationService;
import cn.com.xuxiaowei.boot.oauth2.service.RedisRegisteredClientRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.lang.annotation.*;

/**
 * 开启 OAuth 2.1 Redis 实现
 *
 * @author xuxiaowei
 * @since 2.0.0
 */
@Documented
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import({ EnableOAuth2Redis.OAuth2RedisConfig.class, SpringAuthorizationServerRedisProperties.class })
public @interface EnableOAuth2Redis {

	/**
	 * OAuth 2.1 Redis 所需要的 接口 {@link Bean}
	 *
	 * @author xuxiaowei
	 * @since 2.0.0
	 */
	class OAuth2RedisConfig {

		/**
		 * 客户表 oauth2_registered_client 的 Redis 接口 实现 的 {@link Bean}
		 * @param jdbcOperations 数据源
		 * @param stringRedisTemplate 用于调用 Redis 的 {@link Bean}
		 * @param properties Redis 配置，如：储存前缀、超时时间
		 */
		@Bean
		public RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations,
				StringRedisTemplate stringRedisTemplate, SpringAuthorizationServerRedisProperties properties) {
			return new RedisRegisteredClientRepository(jdbcOperations, stringRedisTemplate, properties);
		}

		/**
		 * 授权表 oauth2_authorization 的接口 Redis 实现 的 {@link Bean}
		 * @param jdbcOperations 数据源
		 * @param registeredClientRepository 客户表接口
		 * @param stringRedisTemplate 用于调用 Redis 的 {@link Bean}
		 * @param properties Redis 配置，如：储存前缀、超时时间
		 */
		@Bean
		public OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations,
				RegisteredClientRepository registeredClientRepository, StringRedisTemplate stringRedisTemplate,
				SpringAuthorizationServerRedisProperties properties) {
			return new RedisOAuth2AuthorizationService(jdbcOperations, registeredClientRepository, stringRedisTemplate,
					properties);
		}

		/**
		 * 手动授权表 oauth2_authorization_consent 的接口 Redis 实现 的 {@link Bean}
		 * @param jdbcOperations 数据源
		 * @param registeredClientRepository 客户表接口
		 * @param stringRedisTemplate 用于调用 Redis 的 {@link Bean}
		 * @param properties Redis 配置，如：储存前缀、超时时间
		 */
		@Bean
		public OAuth2AuthorizationConsentService authorizationConsentService(JdbcOperations jdbcOperations,
				RegisteredClientRepository registeredClientRepository, StringRedisTemplate stringRedisTemplate,
				SpringAuthorizationServerRedisProperties properties) {
			return new RedisOAuth2AuthorizationConsentService(jdbcOperations, registeredClientRepository,
					stringRedisTemplate, properties);
		}

	}

}

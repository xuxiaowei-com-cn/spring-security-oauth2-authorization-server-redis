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
 * @author xuxiaowei
 * @since 2.0.0
 */
@Documented
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import({ EnableOAuth2Redis.OAuth2JdbcConfig.class, SpringAuthorizationServerRedisProperties.class })
public @interface EnableOAuth2Redis {

	class OAuth2JdbcConfig {

		@Bean
		public RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations,
				StringRedisTemplate stringRedisTemplate, SpringAuthorizationServerRedisProperties properties) {
			return new RedisRegisteredClientRepository(jdbcOperations, stringRedisTemplate, properties);
		}

		@Bean
		public OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations,
				RegisteredClientRepository registeredClientRepository, StringRedisTemplate stringRedisTemplate,
				SpringAuthorizationServerRedisProperties properties) {
			return new RedisOAuth2AuthorizationService(jdbcOperations, registeredClientRepository, stringRedisTemplate,
					properties);
		}

		@Bean
		public OAuth2AuthorizationConsentService authorizationConsentService(JdbcOperations jdbcOperations,
				RegisteredClientRepository registeredClientRepository, StringRedisTemplate stringRedisTemplate,
				SpringAuthorizationServerRedisProperties properties) {
			return new RedisOAuth2AuthorizationConsentService(jdbcOperations, registeredClientRepository,
					stringRedisTemplate, properties);
		}

	}

}

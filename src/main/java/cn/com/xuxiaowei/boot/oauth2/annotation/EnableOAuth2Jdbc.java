package cn.com.xuxiaowei.boot.oauth2.annotation;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.lang.annotation.*;

/**
 * 开启 OAuth 2.1 JDBC 实现
 *
 * @author xuxiaowei
 * @since 2.0.0
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Import({ EnableOAuth2Jdbc.OAuth2JdbcConfig.class })
public @interface EnableOAuth2Jdbc {

	/**
	 * OAuth 2.1 JDBC 所需要的 接口 {@link Bean}
	 *
	 * @author xuxiaowei
	 * @since 2.0.0
	 */
	class OAuth2JdbcConfig {

		/**
		 * 客户表 oauth2_registered_client 的 JDBC 接口 实现 的 {@link Bean}
		 * @param jdbcOperations 数据源
		 */
		@Bean
		public RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations) {
			return new JdbcRegisteredClientRepository(jdbcOperations);
		}

		/**
		 * 授权表 oauth2_authorization 的接口 JDBC 实现 的 {@link Bean}
		 * @param jdbcOperations 数据源
		 * @param registeredClientRepository 客户表接口
		 */
		@Bean
		public OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations,
				RegisteredClientRepository registeredClientRepository) {
			return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
		}

		/**
		 * 手动授权表 oauth2_authorization_consent 的接口 JDBC 实现 的 {@link Bean}
		 * @param jdbcOperations 数据源
		 * @param registeredClientRepository 客户表接口
		 */
		@Bean
		public OAuth2AuthorizationConsentService authorizationConsentService(JdbcOperations jdbcOperations,
				RegisteredClientRepository registeredClientRepository) {
			return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, registeredClientRepository);
		}

	}

}

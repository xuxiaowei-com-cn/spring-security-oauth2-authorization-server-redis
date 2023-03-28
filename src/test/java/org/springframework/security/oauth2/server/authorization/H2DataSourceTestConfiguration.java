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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.utils.ObjectMapperUtils;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;

import javax.sql.DataSource;
import java.security.Principal;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

/**
 * 测试 数据源
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
@TestConfiguration
public class H2DataSourceTestConfiguration {

	/**
	 * ID
	 */
	public static final String ID = "bcc73542-6c8e-44e7-a1b4-51f1c4089268";

	/**
	 * 权限ID
	 */
	public static final String AUTHORIZATION_ID = "c703d612-e89b-48a9-b951-b24251fa58c2";

	/**
	 * 客户ID
	 */
	public static final String CLIENT_ID = "xuxiaowei_client_id";

	/**
	 *
	 */
	public static final String ACCESS_TOKEN_VALUE = "d8e3e7c0-3ca0-4797-a30b-51385a47f921";

	/**
	 *
	 */
	public static final String REFRESH_TOKEN_VALUE = "d8e3e7c0-3ca0-4797-a30b-51385a47f921";

	/**
	 *
	 */
	public static final String STATE = "ad33a641-a8c6-4c3b-9e97-379694dfd9da";

	/**
	 * 使用 H2 来创建用于测试的 {@link DataSource}
	 */
	@Bean
	public DataSource dataSource() throws JsonProcessingException {

		// 创建测试数据源
		// @formatter:off
		EmbeddedDatabase dataSource = new EmbeddedDatabaseBuilder().generateUniqueName(true)
			.setType(EmbeddedDatabaseType.H2)
			.setScriptEncoding("UTF-8")
			// 插入表结构
			.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
			.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
			.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
			.build();
		// @formatter:on

		// 创建用于测试的客户信息
		saveClient(dataSource);

		// 创建用于测试的授权信息
		saveAuthorization(dataSource);

		return dataSource;
	}

	/**
	 * 创建用于测试的客户信息
	 */
	private void saveClient(DataSource dataSource) throws JsonProcessingException {

		JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
		// @formatter:off
		JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		// @formatter:on
		RegisteredClient.Builder registeredClientBuilder = RegisteredClient.withId(ID);
		// 客户ID
		registeredClientBuilder.clientId(CLIENT_ID);
		// 客户凭证
		registeredClientBuilder.clientSecret("{noop}xuxiaowei_client_secret");
		// 客户凭证验证方式
		registeredClientBuilder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		registeredClientBuilder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
		// 授权类型
		registeredClientBuilder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
		registeredClientBuilder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
		registeredClientBuilder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
		// 授权成功后重定向地址
		registeredClientBuilder.redirectUri("http://127.0.0.1:1401/code");
		// 授权范围
		registeredClientBuilder.scope("snsapi_base");

		ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder();
		clientSettingsBuilder.requireAuthorizationConsent(true);
		ClientSettings clientSettings = clientSettingsBuilder.build();

		RegisteredClient registeredClient = registeredClientBuilder.clientSettings(clientSettings).build();

		jdbcRegisteredClientRepository.save(registeredClient);

		ObjectMapper objectMapper = ObjectMapperUtils.redis();
		ObjectWriter objectWriter = objectMapper.writerWithDefaultPrettyPrinter();

		RegisteredClient registeredClientByDatabase = jdbcRegisteredClientRepository.findById(ID);
		log.info("检查数据库初始化结果 RegisteredClient：{}", objectWriter.writeValueAsString(registeredClientByDatabase));
	}

	/**
	 * 创建用于测试的授权信息
	 *
	 * @see OAuth2AuthorizationCodeAuthenticationConverter
	 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
	 */
	private void saveAuthorization(DataSource dataSource) throws JsonProcessingException {
		JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
		// @formatter:off
		JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, jdbcRegisteredClientRepository);
		// @formatter:on

		RegisteredClient registeredClient = jdbcRegisteredClientRepository.findById(ID);
		assert registeredClient != null;

		LocalDateTime localDateTime = LocalDateTime.of(2023, 3, 28, 13, 30, 0);
		ZonedDateTime zonedDateTime = localDateTime.atZone(ZoneId.systemDefault());
		Instant issuedAt = Instant.ofEpochMilli(zonedDateTime.toInstant().toEpochMilli());
		Instant expiresAt = issuedAt.plus(3650, ChronoUnit.DAYS);
		// @formatter:off
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, ACCESS_TOKEN_VALUE, issuedAt, expiresAt);
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(REFRESH_TOKEN_VALUE, issuedAt.plus(3650, ChronoUnit.DAYS));
		// @formatter:on

		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
			.id(AUTHORIZATION_ID)
			.principalName("zhang-san")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.accessToken(accessToken)
			.refreshToken(refreshToken)
			.attribute(Principal.class.getName(), principal())
			.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest(registeredClient))
			.build();

		jdbcOAuth2AuthorizationService.save(authorization);

		ObjectMapper objectMapper = ObjectMapperUtils.redis();
		ObjectWriter objectWriter = objectMapper.writerWithDefaultPrettyPrinter();

		OAuth2Authorization auth2AuthorizationByDatabase = jdbcOAuth2AuthorizationService.findById(AUTHORIZATION_ID);
		log.info("检查数据库初始化结果 OAuth2Authorization：{}", objectWriter.writeValueAsString(auth2AuthorizationByDatabase));
	}

	public static Authentication principal() {
		List<GrantedAuthority> authorities = new ArrayList<>();
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority("student");
		authorities.add(authority);
		User user = new User("zhang-san", "", authorities);
		return new UsernamePasswordAuthenticationToken(user, null);
	}

	public static OAuth2AuthorizationRequest authorizationRequest(RegisteredClient registeredClient) {
		return OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri("http://192.168.1.101:1401/oauth2/authorize")
			.clientId(registeredClient.getClientId())
			.redirectUri("http://127.0.0.1:1401/code")
			.scopes(Collections.singleton("snsapi_base"))
			.state(STATE)
			.additionalParameters(new HashMap<>())
			.build();
	}

}

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
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.configuration.RedisSpringAuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.properties.SpringAuthorizationServerRedisProperties;
import org.springframework.security.oauth2.server.authorization.utils.ObjectMapperUtils;

import javax.sql.DataSource;
import java.security.Principal;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.springframework.security.oauth2.server.authorization.H2DataSourceTestConfiguration.*;

/**
 * {@link OAuth2AuthorizationService} 测试类
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
@Import(H2DataSourceTestConfiguration.class)
@SpringBootTest(classes = { RedisAutoConfiguration.class, RedisSpringAuthorizationServerConfiguration.class,
		SpringAuthorizationServerRedisProperties.class, RedisOAuth2AuthorizationService.class })
class RedisOAuth2AuthorizationServiceTests {

	@Autowired
	private RedisOAuth2AuthorizationService redisOAuth2AuthorizationService;

	private JdbcRegisteredClientRepository jdbcRegisteredClientRepository;

	private JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService;

	@Autowired
	public void setJdbcOAuth2AuthorizationService(DataSource dataSource) {
		JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
		// @formatter:off
		this.jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		this.jdbcOAuth2AuthorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, jdbcRegisteredClientRepository);
		// @formatter:on
	}

	@Test
	void save() throws JsonProcessingException {
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

		String id = UUID.randomUUID().toString();

		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
			.id(id)
			.principalName("zhang-san")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.accessToken(accessToken)
			.refreshToken(refreshToken)
			.attribute(Principal.class.getName(), principal())
			.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest(registeredClient))
			.build();

		redisOAuth2AuthorizationService.save(authorization);

		ObjectMapper objectMapper = ObjectMapperUtils.redis();
		ObjectWriter objectWriter = objectMapper.writerWithDefaultPrettyPrinter();

		OAuth2Authorization auth2AuthorizationByDatabase = jdbcOAuth2AuthorizationService.findById(id);
		log.info("直接查询数据库中的保存的结果：{}", objectWriter.writeValueAsString(auth2AuthorizationByDatabase));
	}

	@Test
	void remove() {
		String id = "9db42fc5-8454-4b34-9c1a-660183820504";
		String token = "d8e3e7c0-3ca0-4797-a30b-51385a47f921";

		LocalDateTime localDateTime = LocalDateTime.of(2023, 3, 28, 13, 30, 0);
		ZonedDateTime zonedDateTime = localDateTime.atZone(ZoneId.systemDefault());
		Instant issuedAt = Instant.ofEpochMilli(zonedDateTime.toInstant().toEpochMilli());
		Instant expiresAt = issuedAt.plus(3650, ChronoUnit.DAYS);
		// @formatter:off
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token, issuedAt, expiresAt);
		// @formatter:on

		RegisteredClient registeredClient = RegisteredClient.withId(ID)
			.clientId(CLIENT_ID)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri("http://127.0.0.1:1401/code")
			.build();
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
			.id(id)
			.principalName("zhang-san")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.accessToken(accessToken)
			.build();
		redisOAuth2AuthorizationService.remove(authorization);
	}

	@Test
	void findById() throws JsonProcessingException {
		ObjectMapper objectMapper = ObjectMapperUtils.redis();
		ObjectWriter objectWriter = objectMapper.writerWithDefaultPrettyPrinter();

		OAuth2Authorization auth2Authorization = redisOAuth2AuthorizationService.findById(AUTHORIZATION_ID);
		log.info("根据 id：{} 查询Redis中的授权（不存在时从数据库中查询）：{}", ID, objectWriter.writeValueAsString(auth2Authorization));
		OAuth2Authorization byId = redisOAuth2AuthorizationService.findById(AUTHORIZATION_ID);
		log.info("\n{}", objectWriter.writeValueAsString(byId));
	}

	@Test
	void findByToken() {

	}

}

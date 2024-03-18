package cn.com.xuxiaowei.boot.oauth2.service;

import cn.com.xuxiaowei.boot.oauth2.SpringSecurityOauth2AuthorizationServerRedisApplication;
import cn.com.xuxiaowei.boot.oauth2.annotation.EnableOAuth2Redis;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * 表 oauth2_registered_client 的 Redis 实现 的 单元测试类
 *
 * @author xuxiaowei
 * @since 2.0.0
 */
@Slf4j
@EnableOAuth2Redis
@SpringBootTest(classes = SpringSecurityOauth2AuthorizationServerRedisApplication.class,
		webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class RedisRegisteredClientRepositoryTests {

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private StringRedisTemplate stringRedisTemplate;

	@Autowired
	private RedisRegisteredClientRepository redisRegisteredClientRepository;

	@Test
	void start() throws JsonProcessingException {

		PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

		String id = UUID.randomUUID().toString();
		String clientId = UUID.randomUUID().toString();
		String clientSecret = UUID.randomUUID().toString();
		String encode = passwordEncoder.encode(clientSecret);

		RegisteredClient registeredClient = RegisteredClient.withId(id)
			.clientId(clientId)
			.clientSecret(encode)
			.clientSecretExpiresAt(Instant.now().plus(3650, ChronoUnit.DAYS))
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
			.redirectUri("http://127.0.0.1:8080/authorized")
			.scope(OidcScopes.OPENID)
			.scope(OidcScopes.PROFILE)
			.scope("message.read")
			.scope("message.write")
			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
			.build();

		redisRegisteredClientRepository.save(registeredClient);

		JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(
				jdbcTemplate);

		RegisteredClient findById = jdbcRegisteredClientRepository.findById(id);
		assertNotNull(findById);

		RegisteredClient byClientId = jdbcRegisteredClientRepository.findByClientId(clientId);
		assertNotNull(byClientId);

		for (int i = 0; i < 2; i++) {

			RegisteredClient findByIdRedis = redisRegisteredClientRepository.findById(id);
			assertNotNull(findByIdRedis);

			RegisteredClient findByClientIdRedis = redisRegisteredClientRepository.findByClientId(clientId);
			assertNotNull(findByClientIdRedis);

			ObjectMapper objectMapper = redisRegisteredClientRepository.getObjectMapper();

			String idKey = redisRegisteredClientRepository.idKey(id);
			String getById = stringRedisTemplate.opsForValue().get(idKey);
			assertNotNull(getById);
			RegisteredClient getByIdRegisteredClient = objectMapper.readValue(getById, RegisteredClient.class);
			assertEquals(registeredClient, getByIdRegisteredClient);

			String clientIdKey = redisRegisteredClientRepository.clientIdKey(clientId);
			String getByClientId = stringRedisTemplate.opsForValue().get(clientIdKey);
			assertNotNull(getByClientId);
			RegisteredClient getByClientIdRegisteredClient = objectMapper.readValue(getByClientId,
					RegisteredClient.class);
			assertEquals(registeredClient, getByClientIdRegisteredClient);
		}
	}

}

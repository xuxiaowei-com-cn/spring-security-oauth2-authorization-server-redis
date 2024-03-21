package cn.com.xuxiaowei.boot.oauth2;

import cn.com.xuxiaowei.boot.oauth2.annotation.EnableOAuth2Jdbc;
import cn.com.xuxiaowei.boot.oauth2.annotation.EnableOAuth2Redis;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * OAuth 2.1 Redis 实现的 凭证式 集成测试类
 *
 * @author xuxiaowei
 * @since 2.0.0
 */
@Slf4j
@EnableOAuth2Redis
@SpringBootTest(classes = SpringSecurityOauth2AuthorizationServerRedisApplication.class,
		webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ClientCredentialsTests {

	@LocalServerPort
	private int serverPort;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	// @formatter:off
	/**
	 * 使用 {@link EnableOAuth2Redis} 注解，循环 10 次使用 凭证式，日志仅打印 5 次 oauth2_registered_client 表：<p>
	 * 1. 创建 oauth2_registered_client 表结构<p>
	 * 2. 保存数据前，查询主键 id 是否重复<p>
	 * 3. 保存数据前，查询客户ID client_id 是否重复<p>
	 * 4. 保存数据前，查询客户秘钥 client_secret 是否重复<p>
	 * 5. 保存数据<p>
	 * <p>
	 * 使用 {@link EnableOAuth2Jdbc} 注解，循环 10 次使用 凭证式，日志仅打印 15 次 oauth2_registered_client 表：<p>
	 * 1. 前 5 次与上方相同<p>
	 * 2. 后 10 次都是根据 客户ID client_id 查询<p>
	 */
	// @formatter:on
	@Test
	void start() throws JsonProcessingException {

		PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

		String id = UUID.randomUUID().toString();
		String clientId = UUID.randomUUID().toString();
		String clientSecret = UUID.randomUUID().toString();
		String encode = passwordEncoder.encode(clientSecret);

		// 创建随机客户
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
			.redirectUri("https://home.baidu.com/home/index/contact_us")
			.scope(OidcScopes.OPENID)
			.scope(OidcScopes.PROFILE)
			.scope("message.read")
			.scope("message.write")
			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
			.build();

		// 保存随机客户
		registeredClientRepository.save(registeredClient);

		for (int i = 0; i < 10; i++) {
			RestTemplate restTemplate = new RestTemplate();
			HttpHeaders httpHeaders = new HttpHeaders();
			httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			httpHeaders.setBasicAuth(clientId, clientSecret);
			MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
			requestBody.put(OAuth2ParameterNames.GRANT_TYPE, Collections.singletonList("client_credentials"));
			requestBody.put(OAuth2ParameterNames.SCOPE,
					Collections.singletonList("openid profile message.read message.write"));
			HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(requestBody, httpHeaders);

			// OAuth 2.1 凭证式授权
			Map map = restTemplate.postForObject(String.format("http://127.0.0.1:%d/oauth2/token", serverPort),
					httpEntity, Map.class);

			// 返回值不为空
			assertNotNull(map);

			ObjectMapper objectMapper = new ObjectMapper();
			ObjectWriter objectWriter = objectMapper.writerWithDefaultPrettyPrinter();

			log.info("token:\n{}", objectWriter.writeValueAsString(map));

			// 返回值
			// 授权 Token
			assertNotNull(map.get(OAuth2ParameterNames.ACCESS_TOKEN));
			// 授权范围
			assertNotNull(map.get(OAuth2ParameterNames.SCOPE));
			// 授权类型
			assertNotNull(map.get(OAuth2ParameterNames.TOKEN_TYPE));
			// 过期时间
			assertNotNull(map.get(OAuth2ParameterNames.EXPIRES_IN));
		}
	}

}

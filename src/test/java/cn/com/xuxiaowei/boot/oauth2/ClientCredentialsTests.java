package cn.com.xuxiaowei.boot.oauth2;

import cn.com.xuxiaowei.boot.oauth2.annotation.EnableOAuth2Redis;
import cn.com.xuxiaowei.boot.oauth2.service.RedisRegisteredClientRepository;
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
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
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
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
@EnableOAuth2Redis
@SpringBootTest(classes = SpringSecurityOauth2AuthorizationServerRedisApplication.class,
		webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ClientCredentialsTests {

	@LocalServerPort
	private int serverPort;

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
			.redirectUri("https://home.baidu.com/home/index/contact_us")
			.scope(OidcScopes.OPENID)
			.scope(OidcScopes.PROFILE)
			.scope("message.read")
			.scope("message.write")
			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
			.build();

		redisRegisteredClientRepository.save(registeredClient);

		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		httpHeaders.setBasicAuth(clientId, clientSecret);
		MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
		requestBody.put("grant_type", Collections.singletonList("client_credentials"));
		requestBody.put("scope", Collections.singletonList("openid profile message.read message.write"));
		HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(requestBody, httpHeaders);

		Map map = restTemplate.postForObject(String.format("http://127.0.0.1:%d/oauth2/token", serverPort), httpEntity,
				Map.class);

		assertNotNull(map);

		ObjectMapper objectMapper = new ObjectMapper();
		ObjectWriter objectWriter = objectMapper.writerWithDefaultPrettyPrinter();

		log.info("token:\n{}", objectWriter.writeValueAsString(map));

		assertNotNull(map.get("access_token"));
		assertNotNull(map.get("scope"));
		assertNotNull(map.get("token_type"));
		assertNotNull(map.get("expires_in"));
	}

}

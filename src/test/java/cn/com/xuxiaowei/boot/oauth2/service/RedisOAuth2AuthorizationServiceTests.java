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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.security.Principal;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * 表 oauth2_authorization 的 Redis 实现 的 单元测试类
 *
 * @author xuxiaowei
 * @since 2.0.0
 */
@Slf4j
@EnableOAuth2Redis
@SpringBootTest(classes = SpringSecurityOauth2AuthorizationServerRedisApplication.class,
		webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RedisOAuth2AuthorizationServiceTests {

	@Autowired
	private StringRedisTemplate stringRedisTemplate;

	@Autowired
	private RedisOAuth2AuthorizationService redisOAuth2AuthorizationService;

	@Autowired
	private RedisRegisteredClientRepository redisRegisteredClientRepository;

	@Test
	void start() throws JsonProcessingException {

		PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

		String id = UUID.randomUUID().toString();
		String clientId = UUID.randomUUID().toString();
		String clientSecret = UUID.randomUUID().toString();
		String encode = passwordEncoder.encode(clientSecret);
		String state = UUID.randomUUID().toString();

		String username = "user1";
		Set<GrantedAuthority> authorities = new HashSet<>();
		authorities.add(new SimpleGrantedAuthority("programmer"));
		authorities.add(new SimpleGrantedAuthority("a"));

		String remoteAddress = "192.168.5.4";
		String sessionId = UUID.randomUUID().toString();

		RegisteredClient registeredClient = RegisteredClient.withId(id)
			.clientId(clientId)
			.clientSecret(encode)
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

		String oauth2AuthorizationId = UUID.randomUUID().toString();
		String principalName = UUID.randomUUID().toString();
		AuthorizationGrantType authorizationCode = AuthorizationGrantType.AUTHORIZATION_CODE;
		Set<String> authorizedScopes = new HashSet<>();
		authorizedScopes.add("S1");

		OAuth2AccessToken.TokenType tokenType = OAuth2AccessToken.TokenType.BEARER;
		String tokenValue = UUID.randomUUID().toString();

		Instant issuedAt = Instant.now();
		Instant expiresAt = Instant.now().plusSeconds(1000);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(tokenType, tokenValue, issuedAt, expiresAt);

		String refreshTokenTokenValue = UUID.randomUUID().toString();

		Instant refreshTokenIssuedAt = Instant.now();
		Instant refreshTokenExpiresAt = Instant.now().plusSeconds(2000);

		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(refreshTokenTokenValue, refreshTokenIssuedAt,
				refreshTokenExpiresAt);

		OAuth2AuthorizationRequest auth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.redirectUri("http://127.0.0.1:8080/authorized")
			.authorizationUri("http://127.0.0.1:8080/oauth2/")
			.clientId(clientId)
			.build();

		User user = new User(username, "1", authorities);
		UsernamePasswordAuthenticationToken principal = UsernamePasswordAuthenticationToken.authenticated(user, null,
				authorities);
		WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails(remoteAddress, sessionId);
		principal.setDetails(webAuthenticationDetails);
		principal.eraseCredentials();

		OAuth2Authorization oauth2Authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
			.id(oauth2AuthorizationId)
			.principalName(principalName)
			.authorizationGrantType(authorizationCode)
			.authorizedScopes(authorizedScopes)
			.accessToken(accessToken)
			.refreshToken(refreshToken)
			.attributes(attributesConsumer -> {
				attributesConsumer.put(OAuth2AuthorizationRequest.class.getName(), auth2AuthorizationRequest);
				attributesConsumer.put(Principal.class.getName(), principal);
				attributesConsumer.put("state", state);
				attributesConsumer.put("a", 3);
				attributesConsumer.put("name", "徐晓伟");
			})
			.build();

		redisOAuth2AuthorizationService.save(oauth2Authorization);

		OAuth2Authorization oauth2AuthorizationFindById = redisOAuth2AuthorizationService
			.findById(oauth2AuthorizationId);
		assertNotNull(oauth2AuthorizationFindById);
		// 保存到数据库后，时间精度不足
		// assertEquals(oauth2Authorization, oauth2AuthorizationFindById);

		String idKey = redisOAuth2AuthorizationService.idKey(oauth2Authorization.getId());

		Map<Object, Object> entries = stringRedisTemplate.opsForHash().entries(idKey);
		assertNotNull(entries);

		Object idValue = entries.get("id");
		assertNotNull(idValue);

		ObjectMapper objectMapper = redisOAuth2AuthorizationService.getObjectMapper();
		OAuth2Authorization oauth2AuthorizationByRedis = objectMapper.readValue(idValue.toString(),
				OAuth2Authorization.class);
		assertNotNull(oauth2AuthorizationByRedis);

		// @formatter:off
		assertEquals(oauth2Authorization.getId(), oauth2AuthorizationByRedis.getId());
		assertEquals(oauth2Authorization.getRegisteredClientId(), oauth2AuthorizationByRedis.getRegisteredClientId());
		assertEquals(oauth2Authorization.getPrincipalName(), oauth2AuthorizationByRedis.getPrincipalName());
		assertEquals(oauth2Authorization.getAuthorizationGrantType(), oauth2AuthorizationByRedis.getAuthorizationGrantType());
		assertEquals(oauth2Authorization.getAuthorizedScopes(), oauth2AuthorizationByRedis.getAuthorizedScopes());
		OAuth2Authorization.Token<OAuth2AccessToken> accessToken1 = oauth2Authorization.getAccessToken();
		OAuth2Authorization.Token<OAuth2AccessToken> accessToken2 = oauth2AuthorizationByRedis.getAccessToken();
//		assertEquals(oauth2Authorization.getAccessToken(), oauth2AuthorizationByRedis.getAccessToken());
//		assertEquals(oauth2Authorization.getRefreshToken(), oauth2AuthorizationByRedis.getRefreshToken());
//		assertEquals(oauth2Authorization.getToken(), oauth2AuthorizationByRedis.getToken());
//		assertEquals(oauth2Authorization.getToken(), oauth2AuthorizationByRedis.getToken());

		Map<String,Object> attributes1 = oauth2Authorization.getAttributes();
		Map<String,Object> attributes2 = oauth2AuthorizationByRedis.getAttributes();
		assertEquals(attributes1.get("a"), attributes2.get("a"));
		assertEquals(attributes1.get("name"), attributes2.get("name"));
		assertEquals(attributes1.get("state"), attributes2.get("state"));
		assertEquals(attributes1.get(Principal.class.getName()), attributes2.get(Principal.class.getName()));
//		assertEquals(oauth2Authorization.getAttributes(), oauth2AuthorizationByRedis.getAttributes());

		OAuth2AuthorizationRequest oauth2AuthorizationRequest1 = (OAuth2AuthorizationRequest) attributes1.get(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationRequest oauth2AuthorizationRequest2 = (OAuth2AuthorizationRequest) attributes2.get(OAuth2AuthorizationRequest.class.getName());
//		assertEquals(attributes2.get(OAuth2AuthorizationRequest.class.getName()), attributes2.get(OAuth2AuthorizationRequest.class.getName()));
		assertEquals(oauth2AuthorizationRequest1.getAuthorizationUri(), oauth2AuthorizationRequest2.getAuthorizationUri());
		assertEquals(oauth2AuthorizationRequest1.getGrantType(), oauth2AuthorizationRequest2.getGrantType());
		assertEquals(oauth2AuthorizationRequest1.getResponseType(), oauth2AuthorizationRequest2.getResponseType());
		assertEquals(oauth2AuthorizationRequest1.getClientId(), oauth2AuthorizationRequest2.getClientId());
		assertEquals(oauth2AuthorizationRequest1.getRedirectUri(), oauth2AuthorizationRequest2.getRedirectUri());
		assertEquals(oauth2AuthorizationRequest1.getScopes(), oauth2AuthorizationRequest2.getScopes());
		assertEquals(oauth2AuthorizationRequest1.getState(), oauth2AuthorizationRequest2.getState());
		assertEquals(oauth2AuthorizationRequest1.getAdditionalParameters(), oauth2AuthorizationRequest2.getAdditionalParameters());
		assertEquals(oauth2AuthorizationRequest1.getAttributes(), oauth2AuthorizationRequest2.getAttributes());
//		assertEquals(oauth2AuthorizationRequest1.getAttribute(), oauth2AuthorizationRequest2.getAttribute());
		assertEquals(oauth2AuthorizationRequest1.getAuthorizationRequestUri(), oauth2AuthorizationRequest2.getAuthorizationRequestUri());

//		assertEquals(oauth2Authorization.getAttribute(), oauth2AuthorizationByRedis.getAttribute());
		// assertEquals(oauth2Authorization, oauth2AuthorizationByRedis);
		// @formatter:on

	}

}

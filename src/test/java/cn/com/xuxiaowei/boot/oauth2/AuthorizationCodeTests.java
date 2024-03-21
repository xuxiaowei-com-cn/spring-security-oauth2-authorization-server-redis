package cn.com.xuxiaowei.boot.oauth2;

import cn.com.xuxiaowei.boot.oauth2.annotation.EnableOAuth2Redis;
import cn.com.xuxiaowei.boot.oauth2.service.RedisRegisteredClientRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlCheckBoxInput;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriTemplate;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import static cn.com.xuxiaowei.boot.oauth2.SpringSecurityOauth2AuthorizationServerRedisApplication.password;
import static cn.com.xuxiaowei.boot.oauth2.SpringSecurityOauth2AuthorizationServerRedisApplication.username;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;

/**
 * OAuth 2.1 Redis 实现的 授权码模式 集成测试类
 *
 * @author xuxiaowei
 * @since 2.0.0
 */
@Slf4j
@EnableOAuth2Redis
@AutoConfigureMockMvc
@SpringBootTest(classes = SpringSecurityOauth2AuthorizationServerRedisApplication.class,
		webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthorizationCodeTests {

	@LocalServerPort
	private int serverPort;

	@Autowired
	private WebClient webClient;

	@Autowired
	private RedisRegisteredClientRepository redisRegisteredClientRepository;

	@Test
	void start() throws IOException {

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
			.authorizationGrantType(AUTHORIZATION_CODE)
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
			.redirectUri("http://127.0.0.1:8080/authorized")
			.redirectUri("https://home.baidu.com/home/index/contact_us")
			.scope(OidcScopes.OPENID)
			.scope(OidcScopes.PROFILE)
			.scope("message.read")
			.scope("message.write")
			// 客户配置：需要用户手动授权
			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
			.build();

		// 保存随机客户：保存到 Redis、H2 数据库中
		redisRegisteredClientRepository.save(registeredClient);

		String redirectUri = "https://home.baidu.com/home/index/contact_us";
		String scope = "openid profile message.read message.write";

		// 循环多次，使用授权码模式授权，验证手动授权
		for (int i = 0; i < 3; i++) {
			String state = UUID.randomUUID().toString();

			HtmlPage loginPage = webClient.getPage("/login");

			// 输入用户名、密码
			HtmlInput usernameInput = loginPage.querySelector("input[name=\"username\"]");
			HtmlInput passwordInput = loginPage.querySelector("input[name=\"password\"]");
			usernameInput.type(username);
			passwordInput.type(password);

			// 登录
			HtmlButton signInButton = loginPage.querySelector("button");
			Page signInPage = signInButton.click();
			log.info("signIn Page URL: {}", signInPage.getUrl());

			// 访问授权地址
			HtmlPage authorize = webClient.getPage(
					String.format("/oauth2/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
							clientId, redirectUri, scope, state));

			String authorizeUrl = authorize.getUrl().toString();
			log.info("authorize URL: {}", authorize.getUrl());

			String url;
			if (authorizeUrl.startsWith(redirectUri)) {
				// 若本次授权范围已在历史授权范围内确认过，则自动授权
				url = authorizeUrl;
			}
			else {
				// 首次访问授权地址，需要手动选择授权范围
				HtmlCheckBoxInput profile = authorize.querySelector("input[id=\"profile\"]");
				HtmlCheckBoxInput messageRead = authorize.querySelector("input[id=\"message.read\"]");
				HtmlCheckBoxInput messageWrite = authorize.querySelector("input[id=\"message.write\"]");
				HtmlButton submitButton = authorize.querySelector("button");

				// 勾选授权范围
				profile.setChecked(true);
				messageRead.setChecked(true);
				messageWrite.setChecked(true);

				// 授权
				Page authorized = submitButton.click();
				url = authorized.getUrl().toString();
				log.info("authorized URL: {}", url);
			}

			// 解析授权码
			UriTemplate uriTemplate = new UriTemplate(String.format("%s?code={code}&state={state}", redirectUri));
			Map<String, String> match = uriTemplate.match(url);
			String code = match.get("code");

			// 获取 Token URL
			String tokenUrl = String.format("http://127.0.0.1:%d/oauth2/token", serverPort);

			ObjectMapper objectMapper = new ObjectMapper();
			ObjectWriter objectWriter = objectMapper.writerWithDefaultPrettyPrinter();

			// 获取 Token
			Map<?, ?> token = getToken(clientId, clientSecret, code, redirectUri, tokenUrl);
			log.info("token:\n{}", objectWriter.writeValueAsString(token));

			// 返回值
			// 授权 Token
			assertNotNull(token.get(OAuth2ParameterNames.ACCESS_TOKEN));
			// 使用授权码授权时，并且客户支持刷新 Token，则返回 refresh_token
			assertNotNull(token.get(OAuth2ParameterNames.REFRESH_TOKEN));
			// 授权范围
			assertNotNull(token.get(OAuth2ParameterNames.SCOPE));
			// 授权范围包含 openid 时，会返回 id_token
			// assertNotNull(token.get(RedisConstants.ID_TOKEN));
			// 授权类型
			assertNotNull(token.get(OAuth2ParameterNames.TOKEN_TYPE));
			// 过期时间
			assertNotNull(token.get(OAuth2ParameterNames.EXPIRES_IN));

			// 验证 授权 Token
			String accessToken = token.get(OAuth2ParameterNames.ACCESS_TOKEN).toString();
			RestTemplate restTemplate = new RestTemplate();
			@SuppressWarnings("all")
			ResponseEntity<Map> entity = restTemplate.getForEntity(
					String.format("http://127.0.0.1:%d/user/info?access_token=%s", serverPort, accessToken), Map.class);

			assertEquals(entity.getStatusCodeValue(), 200);

			Map response = entity.getBody();

			assertNotNull(response);

			log.info("\n{}", objectWriter.writeValueAsString(response));

			// 验证 接口返回数据
			assertEquals("徐晓伟", response.get("title"));

			// 验证刷新 Token
			String refreshToken = token.get(OAuth2ParameterNames.REFRESH_TOKEN).toString();
			Map<?, ?> refresh = refreshToken(clientId, clientSecret, refreshToken, tokenUrl);

			assertNotNull(refresh);

			log.info("refresh:\n{}", objectWriter.writeValueAsString(refresh));

			// 返回值
			// 授权 Token
			assertNotNull(refresh.get(OAuth2ParameterNames.ACCESS_TOKEN));
			// 使用授权码授权时，并且客户支持刷新 Token，则返回 refresh_token
			assertNotNull(refresh.get(OAuth2ParameterNames.REFRESH_TOKEN));
			// 授权范围
			assertNotNull(refresh.get(OAuth2ParameterNames.SCOPE));
			// 授权范围包含 openid 时，会返回 id_token
			// assertNotNull(refresh.get(RedisConstants.ID_TOKEN));
			// 授权类型
			assertNotNull(refresh.get(OAuth2ParameterNames.TOKEN_TYPE));
			// 过期时间
			assertNotNull(refresh.get(OAuth2ParameterNames.EXPIRES_IN));
		}
	}

	private Map<?, ?> getToken(String clientId, String clientSecret, String code, String redirectUri, String tokenUrl) {
		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders httpHeaders = new HttpHeaders();
		// 使用 form 提交数据
		httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		httpHeaders.setBasicAuth(clientId, clientSecret);
		MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
		// form 表达数据
		// form 表达数据的值是 List
		requestBody.put(OAuth2ParameterNames.CODE, Collections.singletonList(code));
		requestBody.put(OAuth2ParameterNames.GRANT_TYPE,
				Collections.singletonList(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));
		requestBody.put(OAuth2ParameterNames.REDIRECT_URI, Collections.singletonList(redirectUri));
		HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(requestBody, httpHeaders);

		return restTemplate.postForObject(tokenUrl, httpEntity, Map.class);
	}

	private Map<?, ?> refreshToken(String clientId, String clientSecret, String refreshToken, String tokenUrl) {
		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders httpHeaders = new HttpHeaders();
		// 使用 form 提交数据
		httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		httpHeaders.setBasicAuth(clientId, clientSecret);
		MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
		// form 表达数据
		// form 表达数据的值是 List
		requestBody.put(OAuth2ParameterNames.REFRESH_TOKEN, Collections.singletonList(refreshToken));
		requestBody.put(OAuth2ParameterNames.GRANT_TYPE, Collections.singletonList(OAuth2ParameterNames.REFRESH_TOKEN));
		HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(requestBody, httpHeaders);

		return restTemplate.postForObject(tokenUrl, httpEntity, Map.class);
	}

}

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
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 表 oauth2_authorization_consent 的 Redis 实现 的 单元测试类
 *
 * @author xuxiaowei
 * @since 2.0.0
 */
@Slf4j
@EnableOAuth2Redis
@SpringBootTest(classes = SpringSecurityOauth2AuthorizationServerRedisApplication.class,
		webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RedisOAuth2AuthorizationConsentServiceTests {

	@Autowired
	private StringRedisTemplate stringRedisTemplate;

	@Autowired
	private RedisOAuth2AuthorizationConsentService redisOAuth2AuthorizationConsentService;

	@Test
	void start() throws JsonProcessingException {

		String registeredClientId = UUID.randomUUID().toString();
		String principalName = UUID.randomUUID().toString();

		OAuth2AuthorizationConsent oauth2AuthorizationConsent = OAuth2AuthorizationConsent
			.withId(registeredClientId, principalName)
			.authorities(authoritiesConsumer -> {
				authoritiesConsumer.add(new SimpleGrantedAuthority("A"));
				authoritiesConsumer.add(new SimpleGrantedAuthority("B"));
			})
			.scope("S1")
			.build();

		redisOAuth2AuthorizationConsentService.save(oauth2AuthorizationConsent);

		String key = redisOAuth2AuthorizationConsentService.key(registeredClientId, principalName);

		String json = stringRedisTemplate.opsForValue().get(key);
		assertNotNull(json);

		OAuth2AuthorizationConsent oauth2AuthorizationConsentFindById = redisOAuth2AuthorizationConsentService
			.findById(registeredClientId, principalName);

		assertEquals(oauth2AuthorizationConsent, oauth2AuthorizationConsentFindById);

		ObjectMapper objectMapper = redisOAuth2AuthorizationConsentService.getObjectMapper();

		OAuth2AuthorizationConsent oauth2AuthorizationConsentByJson = objectMapper.readValue(json,
				OAuth2AuthorizationConsent.class);
		assertEquals(oauth2AuthorizationConsent, oauth2AuthorizationConsentByJson);

		redisOAuth2AuthorizationConsentService.remove(oauth2AuthorizationConsent);

		json = stringRedisTemplate.opsForValue().get(key);
		assertNull(json);

	}

}

package org.springframework.security.oauth2.server.authorization;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.server.authorization.configuration.RedisSpringAuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.properties.SpringAuthorizationServerRedisProperties;

/**
 * {@link RedisOAuth2AuthorizationConsentService} 测试类
 * <p>
 * 请修改Redis密码
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
@Import(H2DataSourceTestConfiguration.class)
@SpringBootTest(classes = { RedisAutoConfiguration.class, RedisSpringAuthorizationServerConfiguration.class,
		SpringAuthorizationServerRedisProperties.class, RedisOAuth2AuthorizationConsentService.class })
class RedisOAuth2AuthorizationConsentServiceTests {

	@Autowired
	private RedisOAuth2AuthorizationConsentService redisOAuth2AuthorizationConsentService;

	@Test
	void save() {

	}

	@Test
	void remove() {

	}

	@Test
	void findById() {

	}

}

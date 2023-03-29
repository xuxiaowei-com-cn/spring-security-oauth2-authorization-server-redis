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
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.configuration.RedisSpringAuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.properties.SpringAuthorizationServerRedisProperties;

import javax.sql.DataSource;

import static org.springframework.security.oauth2.server.authorization.H2DataSourceTestConfiguration.ID;

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

	private JdbcOAuth2AuthorizationConsentService jdbcOAuth2AuthorizationConsentService;

	@Autowired
	public void setJdbcOAuth2AuthorizationConsentService(DataSource dataSource) {
		JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
		// @formatter:off
		JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		this.jdbcOAuth2AuthorizationConsentService = new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, jdbcRegisteredClientRepository);
		// @formatter:on
	}

	@Test
	void save() throws JsonProcessingException {
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority("student");
		String principalName = "zhang-san";
		OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(ID, principalName)
			.authority(authority)
			.scope("admin");
		OAuth2AuthorizationConsent authorizationConsent = builder.build();

		jdbcOAuth2AuthorizationConsentService.save(authorizationConsent);

		OAuth2AuthorizationConsent auth2AuthorizationConsent = jdbcOAuth2AuthorizationConsentService.findById(ID,
				principalName);

		ObjectMapper objectMapper = new ObjectMapper();
		log.info(objectMapper.writeValueAsString(auth2AuthorizationConsent));

		findById();
	}

	@Test
	void remove() {
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority("student");
		String principalName = "zhang-san";
		OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(ID, principalName)
			.authority(authority)
			.scope("admin");
		OAuth2AuthorizationConsent authorizationConsent = builder.build();
		redisOAuth2AuthorizationConsentService.remove(authorizationConsent);
	}

	@Test
	void findById() throws JsonProcessingException {
		String principalName = "zhang-san";
		OAuth2AuthorizationConsent byId = redisOAuth2AuthorizationConsentService.findById(ID, principalName);
		ObjectMapper objectMapper = new ObjectMapper();
		log.info(objectMapper.writeValueAsString(byId));
	}

}

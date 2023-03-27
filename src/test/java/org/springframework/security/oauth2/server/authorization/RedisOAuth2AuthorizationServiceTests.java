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
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.configuration.RedisSpringAuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.properties.SpringAuthorizationServerRedisProperties;
import org.springframework.security.oauth2.server.authorization.utils.ObjectMapperUtils;

import javax.sql.DataSource;

import static org.springframework.security.oauth2.server.authorization.H2DataSourceTestConfiguration.AUTHORIZATION_ID;
import static org.springframework.security.oauth2.server.authorization.H2DataSourceTestConfiguration.ID;

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

	private JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService;

	@Autowired
	public void setJdbcOAuth2AuthorizationService(DataSource dataSource) {
		JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
		// @formatter:off
		JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		this.jdbcOAuth2AuthorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, jdbcRegisteredClientRepository);
		// @formatter:on
	}

	@Test
	void save() {

	}

	@Test
	void remove() {

	}

	@Test
	void findById() throws JsonProcessingException {
		ObjectMapper objectMapper = ObjectMapperUtils.redis();
		OAuth2Authorization auth2Authorization = redisOAuth2AuthorizationService.findById(AUTHORIZATION_ID);
		log.info("根据 id：{} 查询Redis中的授权（不存在时从数据库中查询）：{}", ID, objectMapper.writeValueAsString(auth2Authorization));
		OAuth2Authorization byId = redisOAuth2AuthorizationService.findById(AUTHORIZATION_ID);
		log.info(objectMapper.writeValueAsString(byId));
	}

	@Test
	void findByToken() {

	}

}

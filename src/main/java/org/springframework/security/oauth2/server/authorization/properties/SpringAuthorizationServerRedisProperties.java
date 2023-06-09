package org.springframework.security.oauth2.server.authorization.properties;

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

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * spring-authorization-server Redis 配置
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Data
@Component
@ConfigurationProperties(prefix = "spring.authorization-server.redis")
public class SpringAuthorizationServerRedisProperties {

	/**
	 * Redis key 前缀
	 */
	private String prefix = "spring-authorization-server";

	/**
	 * registered client Redis 超时时间，单位为秒
	 */
	private long registeredClientTimeout = 300;

	/**
	 * authorization Redis 超时时间，单位为秒
	 */
	private long authorizationTimeout = 300;

	/**
	 * authorization consent Redis 超时时间，单位为秒
	 */
	private long authorizationConsentTimeout = 300;

}

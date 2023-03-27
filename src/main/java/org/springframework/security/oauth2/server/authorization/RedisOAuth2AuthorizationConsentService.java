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

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * 一个 Redis 的 {@link OAuth2AuthorizationConsentService} 实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see InMemoryOAuth2AuthorizationConsentService
 * @see JdbcOAuth2AuthorizationConsentService
 */
@Slf4j
@Service
public class RedisOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

	@Override
	public void save(OAuth2AuthorizationConsent authorizationConsent) {

	}

	@Override
	public void remove(OAuth2AuthorizationConsent authorizationConsent) {

	}

	@Override
	public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
		return null;
	}

}

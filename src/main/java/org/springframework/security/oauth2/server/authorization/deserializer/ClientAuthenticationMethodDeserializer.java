package org.springframework.security.oauth2.server.authorization.deserializer;

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

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.io.IOException;
import java.util.Map;

/**
 * {@link ClientAuthenticationMethod} 反序列化
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class ClientAuthenticationMethodDeserializer extends StdDeserializer<ClientAuthenticationMethod> {

	public ClientAuthenticationMethodDeserializer() {
		this(null);
	}

	public ClientAuthenticationMethodDeserializer(Class<?> vc) {
		super(vc);
	}

	@Override
	public ClientAuthenticationMethod deserialize(JsonParser p, DeserializationContext ctxt)
			throws IOException, JacksonException {
		ObjectMapper objectMapper = new ObjectMapper();
		Map<String, String> map = objectMapper.readValue(p, new TypeReference<Map<String, String>>() {
		});
		return new ClientAuthenticationMethod(map.values().stream().findFirst().orElse(null));
	}

}

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
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.io.IOException;
import java.util.Map;

/**
 * {@link ClientSettings} 反序列化
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class ClientSettingsDeserializer extends StdDeserializer<ClientSettings> {

	public ClientSettingsDeserializer() {
		this(null);
	}

	public ClientSettingsDeserializer(Class<?> vc) {
		super(vc);
	}

	@Override
	public ClientSettings deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
		ObjectMapper objectMapper = new ObjectMapper();
		Map<String, Object> settings = objectMapper.readValue(p.getCodec().readTree(p).get("settings").toString(),
				new TypeReference<Map<String, Object>>() {
				});
		ClientSettings.Builder builder = ClientSettings.withSettings(settings);
		return builder.build();
	}

}

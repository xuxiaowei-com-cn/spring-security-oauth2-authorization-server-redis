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
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.utils.ObjectMapperUtils;

import java.io.IOException;
import java.util.Map;

/**
 * {@link OAuth2Authorization} 反序列化
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class OAuth2AuthorizationDeserializer extends StdDeserializer<OAuth2Authorization> {

	public OAuth2AuthorizationDeserializer() {
		this(null);
	}

	public OAuth2AuthorizationDeserializer(Class<?> vc) {
		super(vc);
	}

	@Override
	public OAuth2Authorization deserialize(JsonParser p, DeserializationContext ctxt)
			throws IOException, JacksonException {
		ObjectMapper objectMapper = ObjectMapperUtils.redis();

		TreeNode treeNode = p.getCodec().readTree(p);
		String s = treeNode.toString();
		@SuppressWarnings("all")
		Map<String, String> map = new ObjectMapper().readValue(s, Map.class);
		map.put("@class", OAuth2Authorization.class.getName());

		map.remove("accessToken");
		// map.remove("authorizationGrantType");

		String s1 = new ObjectMapper().writeValueAsString(map);

		OAuth2Authorization authorization = objectMapper.readValue(s1, OAuth2Authorization.class);

		return null;
	}

}

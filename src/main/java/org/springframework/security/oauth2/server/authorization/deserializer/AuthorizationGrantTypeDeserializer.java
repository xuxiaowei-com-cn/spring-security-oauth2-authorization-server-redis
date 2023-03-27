package org.springframework.security.oauth2.server.authorization.deserializer;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import lombok.SneakyThrows;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.io.IOException;
import java.util.Map;

/**
 * {@link AuthorizationGrantType} 反序列化
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class AuthorizationGrantTypeDeserializer extends StdDeserializer<AuthorizationGrantType> {

	public AuthorizationGrantTypeDeserializer() {
		this(null);
	}

	public AuthorizationGrantTypeDeserializer(Class<?> vc) {
		super(vc);
	}

	@Override
	public AuthorizationGrantType deserialize(JsonParser p, DeserializationContext ctxt)
			throws IOException, JacksonException {
		TreeNode treeNode = p.getCodec().readTree(p);
		return treeNodeToAuthorizationGrantType(treeNode);
	}

	@SneakyThrows
	public static AuthorizationGrantType treeNodeToAuthorizationGrantType(TreeNode treeNode) {
		String string = treeNode.toString();
		ObjectMapper objectMapper = new ObjectMapper();
		@SuppressWarnings("all")
		Map<String, String> map = objectMapper.readValue(string, Map.class);
		for (String value : map.values()) {
			return new AuthorizationGrantType(value);
		}
		return null;
	}

}

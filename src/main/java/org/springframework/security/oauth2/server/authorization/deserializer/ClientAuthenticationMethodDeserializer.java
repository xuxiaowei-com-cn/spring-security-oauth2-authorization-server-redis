package org.springframework.security.oauth2.server.authorization.deserializer;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import lombok.SneakyThrows;
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
		TreeNode treeNode = p.getCodec().readTree(p);
		return treeNodeToClientAuthenticationMethod(treeNode);
	}

	@SneakyThrows
	public static ClientAuthenticationMethod treeNodeToClientAuthenticationMethod(TreeNode treeNode) {
		String string = treeNode.toString();
		ObjectMapper objectMapper = new ObjectMapper();
		@SuppressWarnings("all")
		Map<String, String> map = objectMapper.readValue(string, Map.class);
		for (String value : map.values()) {
			return new ClientAuthenticationMethod(value);
		}
		return null;
	}

}

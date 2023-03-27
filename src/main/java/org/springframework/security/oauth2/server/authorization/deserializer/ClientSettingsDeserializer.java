package org.springframework.security.oauth2.server.authorization.deserializer;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import lombok.SneakyThrows;
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
		TreeNode treeNode = p.getCodec().readTree(p);
		Map<String, Object> settings = settingsTreeNodeToMap(treeNode);
		ClientSettings.Builder builder = ClientSettings.withSettings(settings);
		return builder.build();
	}

	@SneakyThrows
	@SuppressWarnings("all")
	public static Map<String, Object> settingsTreeNodeToMap(TreeNode treeNode) {
		TreeNode settingsTreeNode = treeNode.get("settings");
		String string = settingsTreeNode.toString();
		ObjectMapper objectMapper = new ObjectMapper();
		return objectMapper.readValue(string, Map.class);
	}

}

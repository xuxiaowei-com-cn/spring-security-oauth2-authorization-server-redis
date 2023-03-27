package org.springframework.security.oauth2.server.authorization.utils;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class AuthorizationGrantTypeMixin {

    @JsonCreator
    public static AuthorizationGrantType fromString(@JsonProperty("value") String value) {
        return new AuthorizationGrantType(value);
    }

}

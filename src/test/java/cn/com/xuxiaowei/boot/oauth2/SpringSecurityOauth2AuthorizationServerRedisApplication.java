package cn.com.xuxiaowei.boot.oauth2;

import cn.com.xuxiaowei.boot.oauth2.jose.Jwks;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * 此类仅用于测试类加载默认配置
 *
 * @author xuxiaowei
 * @since 2.0.0
 */
@SpringBootApplication
@Configuration(proxyBeanMethods = false)
public class SpringSecurityOauth2AuthorizationServerRedisApplication {

	/**
	 * 默认用户名
	 */
	public static final String username = "user1";

	/**
	 * 默认密码
	 */
	public static final String password = "password";

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityOauth2AuthorizationServerRedisApplication.class, args);
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

		// 开启 OAuth 2.1 配置
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			// Enable
			// OpenID
			// Connect
			// 1.0
			.oidc(Customizer.withDefaults());

		// 未登录时，跳转到 /login 页面
		http.exceptionHandling(
				exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

		return http.build();
	}

	/**
	 * 开启 URL 参数 token 验证，参数名：access_token
	 */
	@Bean
	public BearerTokenResolver bearerTokenResolver() {
		DefaultBearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
		bearerTokenResolver.setAllowUriQueryParameter(true);
		return bearerTokenResolver;
	}

	@Bean
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

		// 默认登陆配置
		// 所有路径均需要授权后才能访问
		http.authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
			.formLogin(withDefaults());

		// 开启 OAuth 2 资源服务配置
		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

		return http.build();
	}

	/**
	 * 用户接口 实现
	 * <p>
	 * 启动程序时，创建一个默认用户
	 * @param dataSource 数据源
	 */
	@Bean
	public UserDetailsService userDetailsService(DataSource dataSource) {

		// 权限
		List<GrantedAuthority> authorities = new ArrayList<>();
		authorities.add(new SimpleGrantedAuthority("programmer"));

		// 密码加密储存
		PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		String encode = passwordEncoder.encode(password);

		// 创建用户
		UserDetails user = new User(username, encode, authorities);

		JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);

		// 将用户保存到数据库
		jdbcUserDetailsManager.createUser(user);

		return jdbcUserDetailsManager;
	}

	/**
	 * 数据库
	 * <p>
	 * 自动化测试，使用 H2 嵌入型数据库
	 */
	@Bean
	public EmbeddedDatabase embeddedDatabase() {
		// @formatter:off
        return new EmbeddedDatabaseBuilder()
                .generateUniqueName(true)
                .setType(EmbeddedDatabaseType.H2)
                .setScriptEncoding("UTF-8")
				// 程序启动后，初始化数据库，创建表结构
                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
                .addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.addScript("org/springframework/security/core/userdetails/jdbc/users.ddl")
                .build();
        // @formatter:on
	}

	/**
	 * OAuth 2.1 加密配置
	 * <p>
	 * 若使用 RSA 秘钥，最少需要 2048 位
	 */
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = Jwks.generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	/**
	 * JWT 解码器，用户验证 JWT 签名
	 */
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	/**
	 * OAuth 2.1 端点配置
	 * <p>
	 * 地址：/.well-known/oauth-authorization-server
	 */
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

}

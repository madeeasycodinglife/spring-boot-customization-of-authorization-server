package com.madeeasy.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Configuration
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc((oidc) -> oidc
                        .userInfoEndpoint((userInfo) -> userInfo
                                .userInfoMapper(userInfoMapper())
                        )
                );
        http.exceptionHandling(exception -> exception
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
        // Accept access tokens for User Info and/or Client Registration
        http.oauth2ResourceServer(resourceServer -> resourceServer.
                jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .formLogin(Customizer.withDefaults())
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                );

        return http.build();
    }
    private Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper() {
        return context -> {
            OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
            JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
            return new OidcUserInfo(principal.getToken().getClaims());
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9000")
                .authorizationEndpoint("/oauth2/authorize") // GET
                .tokenEndpoint("/oauth2/token") // POST
                .tokenIntrospectionEndpoint("/oauth2/introspect") // POST
                .tokenRevocationEndpoint("/oauth2/revoke") //POST
                .jwkSetEndpoint("/oauth2/jwks") // GET
                .oidcUserInfoEndpoint("/userinfo") // GET
                //.oidcClientRegistrationEndpoint("/clientregistration")
                .build();
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(OidcUserInfoService userInfoService) {
        return context -> {
            Authentication principal = context.getPrincipal();
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                context.getClaims().claim("Test", "Test Id Token");
                OidcUserInfo userInfo = userInfoService.loadUser(
                        context.getPrincipal().getName());
                context.getClaims().claims(claims ->
                        claims.putAll(userInfo.getClaims()));
            }
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().claim("Test", "Test Access Token");
                Set<String> authorities = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
                context.getClaims().claim("authorities", authorities)
                        .claim("user", principal.getName());
            }
        };
    }
    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    public static RSAKey generateRsa() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
    }

    static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

}

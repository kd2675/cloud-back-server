package cloud.back.server.config;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfiguration {
    private static final String ACCESS_TOKEN_COOKIE_NAME = "accessToken";

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.oauth2.jwk-set-uri:http://localhost:9000/oauth2/jwks}")
    private String oauthJwkSetUri;

    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder() {
        SecretKey secretKey = new SecretKeySpec(
                jwtSecret.getBytes(StandardCharsets.UTF_8),
                "HmacSHA512"
        );
        ReactiveJwtDecoder legacyHmacDecoder = NimbusReactiveJwtDecoder.withSecretKey(secretKey)
                .macAlgorithm(MacAlgorithm.HS512)
                .build();

        ReactiveJwtDecoder oauthJwtDecoder = NimbusReactiveJwtDecoder.withJwkSetUri(oauthJwkSetUri).build();

        return token -> legacyHmacDecoder.decode(token)
                .onErrorResume(ex -> oauthJwtDecoder.decode(token));
    }

    @Bean
    @Order(1)
    public SecurityWebFilterChain publicEndpointsFilterChain(ServerHttpSecurity http) {
        return http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers(
                        "/auth/login", "/auth/refresh", "/auth/bff/**",
                        "/oauth2/**", "/login/**", "/.well-known/**", "/actuator/**"
                ))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeExchange(exchanges -> exchanges.anyExchange().permitAll())
                .build();
    }

    @Bean
    @Order(2)
    public SecurityWebFilterChain defaultSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.POST, "/api/users").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/muse/v1/home").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/muse/v1/overview").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/muse/v1/contests/**").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/muse/v1/gallery/**").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/muse/v1/artworks/**").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .bearerTokenConverter(bearerTokenAuthenticationConverter())
                        .jwt(Customizer.withDefaults())
                )
                .build();
    }

    @Bean
    public ServerAuthenticationConverter bearerTokenAuthenticationConverter() {
        ServerBearerTokenAuthenticationConverter defaultConverter = new ServerBearerTokenAuthenticationConverter();
        return exchange -> defaultConverter.convert(exchange)
                .switchIfEmpty(Mono.defer(() -> {
                    var cookie = exchange.getRequest().getCookies().getFirst(ACCESS_TOKEN_COOKIE_NAME);
                    if (cookie == null || cookie.getValue() == null || cookie.getValue().isBlank()) {
                        return Mono.empty();
                    }
                    return Mono.just(new org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken(cookie.getValue()));
                }));
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                "http://61.80.148.197:3000",
                "http://localhost:3001",
                "http://127.0.0.1:3001",
                "http://61.80.148.197:3001",
                "http://localhost:3002",
                "http://127.0.0.1:3002",
                "http://61.80.148.197:3002",
                "http://localhost:3003",
                "http://127.0.0.1:3003",
                "http://61.80.148.197:3003"
        ));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}

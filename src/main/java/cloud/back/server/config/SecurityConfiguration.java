package cloud.back.server.config;

import cloud.back.server.security.GatewayServiceAuthenticationConverter;
import cloud.back.server.security.GatewayServiceAuthenticationManager;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import lombok.RequiredArgsConstructor;
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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.security.issuer}")
    private String issuer;

    @Value("${app.cors.allowed-origins}")
    private String allowedOrigins;

    /** 발급 서버 issuer와 HS512 서명을 검증하는 기본 JWT decoder다. */
    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder() {
        SecretKey secretKey = new SecretKeySpec(
                jwtSecret.getBytes(StandardCharsets.UTF_8),
                "HmacSHA512"
        );
        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withSecretKey(secretKey)
                .macAlgorithm(MacAlgorithm.HS512)
                .build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
        return decoder;
    }

    /**
     * 로그인·refresh·OAuth callback처럼 토큰 발급 전에 접근해야 하는 경로만 공개한다.
     */
    @Bean
    @Order(1)
    public SecurityWebFilterChain publicEndpointsFilterChain(ServerHttpSecurity http) {
        return http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers(
                        "/auth/login", "/auth/refresh", "/auth/logout",
                        "/oauth2/**", "/login/**", "/.well-known/**", "/actuator/**"
                ))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeExchange(exchanges -> exchanges.anyExchange().permitAll())
                .build();
    }

    /**
     * /internal/zeroq/gateway/** 요청에 timestamp·nonce·body hash·HMAC 기반 장비 인증을 적용한다.
     */
    @Bean
    @Order(2)
    public SecurityWebFilterChain gatewayServiceFilterChain(
            ServerHttpSecurity http,
            GatewayServiceAuthenticationManager gatewayServiceAuthenticationManager,
            GatewayServiceAuthenticationConverter gatewayServiceAuthenticationConverter
    ) {
        AuthenticationWebFilter gatewayAuthFilter = new AuthenticationWebFilter(gatewayServiceAuthenticationManager);
        gatewayAuthFilter.setServerAuthenticationConverter(gatewayServiceAuthenticationConverter);
        gatewayAuthFilter.setSecurityContextRepository(NoOpServerSecurityContextRepository.getInstance());

        return http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers(
                        "/internal/zeroq/gateway/**",
                        "/internal/stock-batch/v1/jobs/**"
                ))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
                .addFilterAt(gatewayAuthFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    @Bean
    @Order(3)
    public SecurityWebFilterChain stockApiFilterChain(ServerHttpSecurity http) {
        return http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers("/api/stock/**"))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.GET, "/api/stock/v1/system/status").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/stock/v1/markets/**").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtDecoder(audienceDecoder("stock-api"))))
                .build();
    }

    @Bean
    @Order(4)
    public SecurityWebFilterChain museApiFilterChain(ServerHttpSecurity http) {
        return http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers("/api/muse/**"))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.GET, "/api/muse/v1/home", "/api/muse/v1/overview").permitAll()
                        .pathMatchers(HttpMethod.GET, "/api/muse/v1/contests/**", "/api/muse/v1/gallery/**", "/api/muse/v1/artworks/**").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtDecoder(audienceDecoder("muse-api"))))
                .build();
    }

    @Bean
    @Order(5)
    public SecurityWebFilterChain semoApiFilterChain(ServerHttpSecurity http) {
        return serviceApiFilterChain(http, "/api/semo/**", "semo-api");
    }

    /** ZeroQ API에 issuer, zeroq-api audience, api scope 검증을 적용한다. */
    @Bean
    @Order(6)
    public SecurityWebFilterChain zeroqApiFilterChain(ServerHttpSecurity http) {
        return serviceApiFilterChain(http, "/api/zeroq/**", "zeroq-api");
    }

    @Bean
    @Order(10)
    public SecurityWebFilterChain defaultSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.POST, "/api/users").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .build();
    }

    /** 서비스별 path와 audience를 묶어 동일한 JWT 보안 계약을 구성한다. */
    private SecurityWebFilterChain serviceApiFilterChain(
            ServerHttpSecurity http,
            String pathPattern,
            String audience
    ) {
        return http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers(pathPattern))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtDecoder(audienceDecoder(audience))))
                .build();
    }

    /** 공통 서명·issuer 외에 대상 서비스 audience와 api scope를 모두 요구한다. */
    private ReactiveJwtDecoder audienceDecoder(String audience) {
        SecretKey secretKey = new SecretKeySpec(
                jwtSecret.getBytes(StandardCharsets.UTF_8),
                "HmacSHA512"
        );
        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withSecretKey(secretKey)
                .macAlgorithm(MacAlgorithm.HS512)
                .build();
        OAuth2TokenValidator<Jwt> issuerValidator = JwtValidators.createDefaultWithIssuer(issuer);
        OAuth2TokenValidator<Jwt> audienceValidator = new JwtClaimValidator<List<String>>(
                "aud",
                audiences -> audiences != null && audiences.contains(audience)
        );
        OAuth2TokenValidator<Jwt> scopeValidator = new JwtClaimValidator<String>(
                "scope",
                scope -> scope != null && Arrays.asList(scope.split(" ")).contains("api")
        );
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                issuerValidator,
                audienceValidator,
                scopeValidator
        ));
        return decoder;
    }

    /** 설정된 프런트 origin만 credential 포함 CORS 요청을 허용한다. */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(origin -> !origin.isEmpty())
                .toList());
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}

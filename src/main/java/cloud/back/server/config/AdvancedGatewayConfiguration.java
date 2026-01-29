package cloud.back.server.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 고급 Gateway 설정
 * - 요청/응답 필터링
 * - 로깅
 * - 에러 처리
 */
@Configuration
@Slf4j
@RequiredArgsConstructor
public class AdvancedGatewayConfiguration {

    /**
     * 글로벌 요청 필터 - 모든 요청을 로깅합니다
     */
    @Bean
    @Order(-100)
    public GlobalFilter requestLoggingFilter() {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            log.info(">>> Incoming Request");
            log.info("  Method: {}", request.getMethod());
            log.info("  Path: {}", request.getPath());
            log.info("  Query: {}", request.getQueryParams());

            long startTime = System.currentTimeMillis();

            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
                ServerHttpResponse response = exchange.getResponse();
                long duration = System.currentTimeMillis() - startTime;

                log.info("<<< Outgoing Response");
                log.info("  Status: {}", response.getStatusCode());
                log.info("  Duration: {}ms", duration);
            }));
        };
    }

    /**
     * 글로벌 에러 처리 필터
     */
    @Bean
    @Order(-99)
    public GlobalFilter globalErrorFilter() {
        return (exchange, chain) -> {
            return chain.filter(exchange)
                    .onErrorResume(ex -> {
                        log.error("Gateway Error: ", ex);

                        ServerHttpResponse response = exchange.getResponse();
                        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                        response.getHeaders().set("Content-Type", "application/json");

                        String errorBody = "{\"error\": \"" + ex.getMessage() + "\"}";
                        return response.writeWith(
                                Mono.just(response.bufferFactory().wrap(errorBody.getBytes()))
                        );
                    });
        };
    }

    /**
     * 커스텀 라우팅 설정 (더 세밀한 제어)
     */
    @Bean
    public RouteLocator advancedRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                // ============================================================
                // Auth Service - 인증 관련 엔드포인트
                // ============================================================
                .route("auth-login", r -> r
                        .path("/auth/login")
                        .and().method(HttpMethod.POST)
                        .filters(f -> f.addRequestHeader("X-Gateway", "true"))
                        .uri("lb://auth-service")
                )

                .route("auth-refresh", r -> r
                        .path("/auth/refresh")
                        .and().method(HttpMethod.POST)
                        .uri("lb://auth-service")
                )

                .route("auth-logout", r -> r
                        .path("/auth/logout")
                        .and().method(HttpMethod.POST)
                        .uri("lb://auth-service")
                )

                .route("auth-validate", r -> r
                        .path("/auth/validate")
                        .and().method(HttpMethod.POST)
                        .uri("lb://auth-service")
                )

                .route("auth-jwks", r -> r
                        .path("/.well-known/jwks.json")
                        .and().method(HttpMethod.GET)
                        .uri("lb://auth-service")
                )

                // ============================================================
                // Health Check Endpoints (인증 제외)
                // ============================================================
                .route("actuator-health", r -> r
                        .path("/actuator/health")
                        .and().method(HttpMethod.GET)
                        .uri("lb://auth-service")
                )

                .route("actuator-info", r -> r
                        .path("/actuator/info")
                        .and().method(HttpMethod.GET)
                        .uri("lb://auth-service")
                )

                // ============================================================
                // 추후 추가할 서비스들 (주석 처리)
                // ============================================================

                // User Service
                // .route("user-service-get-me", r -> r
                //         .path("/api/users/me")
                //         .and().method(HttpMethod.GET)
                //         .filters(f -> f.stripPrefix(1))
                //         .uri("lb://user-service")
                // )
                //
                // .route("user-service-all", r -> r
                //         .path("/api/users/**")
                //         .filters(f -> f.stripPrefix(1))
                //         .uri("lb://user-service")
                // )

                // Order Service
                // .route("order-service", r -> r
                //         .path("/api/orders/**")
                //         .filters(f -> f.stripPrefix(1))
                //         .uri("lb://order-service")
                // )

                // Product Service
                // .route("product-service", r -> r
                //         .path("/api/products/**")
                //         .filters(f -> f.stripPrefix(1))
                //         .uri("lb://product-service")
                // )

                .build();
    }
}

package cloud.back.server.config;

import cloud.back.server.filter.PostLoggingFilter;
import cloud.back.server.filter.PreLoggingFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
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
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Configuration
@Slf4j
@RequiredArgsConstructor
public class AdvancedGatewayConfiguration {

    @Bean
    @LoadBalanced
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }
    
    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

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
    public RouteLocator advancedRouteLocator(RouteLocatorBuilder builder,
                                           PreLoggingFilter preLoggingFilter,
                                           PostLoggingFilter postLoggingFilter) {
        return builder.routes()
                // ============================================================
                // Auth Service - 인증 관련 엔드포인트
                // ============================================================
                .route("auth-login", r -> r
                        .path("/auth/login")
                        .and().method(HttpMethod.POST)
                        .filters(f -> f.addRequestHeader("X-Gateway", "true"))
                        .uri("lb://auth-back-server")
                )

                .route("auth-refresh", r -> r
                        .path("/auth/refresh")
                        .and().method(HttpMethod.POST)
                        .uri("lb://auth-back-server")
                )

                .route("auth-logout", r -> r
                        .path("/auth/logout")
                        .and().method(HttpMethod.POST)
                        .filters(f -> f
                                .filter(preLoggingFilter.apply(new PreLoggingFilter.Config()))
                                .filter(postLoggingFilter.apply(new PostLoggingFilter.Config()))
                        )
                        .uri("lb://auth-back-server")
                )

                .route("auth-validate", r -> r
                        .path("/auth/validate")
                        .and().method(HttpMethod.POST)
                        .uri("lb://auth-back-server")
                )

                .route("auth-oauth2", r -> r
                        .path("/oauth2/**")
                        .uri("lb://auth-back-server")
                )
                // ... (existing routes)
                // ============================================================
                // User Service - 사용자 관리 API (auth-back-server에서 제공)
                // ============================================================
                .route("user-api-all", r -> r
                        .path("/api/users/**")
                        .filters(f -> f
                                .filter(preLoggingFilter.apply(new PreLoggingFilter.Config()))
                                .filter(postLoggingFilter.apply(new PostLoggingFilter.Config()))
                        )
                        .uri("lb://auth-back-server")
                )

                // ============================================================
                // ZeroQ Back Service - Core APIs
                // ============================================================
                .route("zeroq-back-service-api", r -> r
                        .path("/api/v1/**")
                        .filters(f -> f
                                .filter(preLoggingFilter.apply(new PreLoggingFilter.Config()))
                                .filter(postLoggingFilter.apply(new PostLoggingFilter.Config()))
                        )
                        .uri("lb://zeroq-back-service")
                )

                // ... (existing routes)
                .build();
    }
}

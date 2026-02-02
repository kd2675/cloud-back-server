package cloud.back.server.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Gateway JWT 인증 필터
 * - 인증이 필요한 경로에 대해 JWT 토큰 검증
 * - 인증 불필요 경로는 통과
 */
@Slf4j
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final SecretKey secretKey;

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    // 생성자에서 Secret Key 초기화 (성능 최적화)
    public JwtAuthenticationFilter(@Value("${app.jwt.secret}") String jwtSecret) {
        this.secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 인증이 필요 없는 경로 목록
     */
    private static final List<PathPattern> PUBLIC_PATHS = List.of(
            // Auth endpoints
            new PathPattern("/auth/**", null),
            new PathPattern("/login/**", null),
            new PathPattern("/oauth2/**", null),
            new PathPattern("/.well-known/**", null),

            // Actuator
            new PathPattern("/actuator/**", null),

            // User signup (POST only)
            new PathPattern("/api/users", HttpMethod.POST)
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        HttpMethod method = request.getMethod();

        if (isPublicPath(path, method)) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return onError(exchange, "Missing or invalid Authorization header", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);

        try {
            // ⭐ 핵심: 여기서는 토큰의 유효성 검증만 수행합니다.
            Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token);

            // 헤더 추가 로직은 UserHeaderFilter가 담당하므로, 여기서는 그냥 통과시킵니다.
            return chain.filter(exchange);

        } catch (ExpiredJwtException e) {
            return onError(exchange, "Token has expired", HttpStatus.UNAUTHORIZED);
        } catch (JwtException | IllegalArgumentException e) {
            return onError(exchange, "Invalid token", HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * 인증이 필요 없는 경로인지 확인
     */
    private boolean isPublicPath(String path, HttpMethod method) {
        for (PathPattern pattern : PUBLIC_PATHS) {
            if (pathMatcher.match(pattern.path(), path)) {
                // 메서드 제한이 없거나, 메서드가 일치하면 public
                if (pattern.method() == null || pattern.method().equals(method)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 에러 응답 반환
     */
    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().set("Content-Type", "application/json");

        String body = String.format("{\"error\": \"%s\", \"status\": %d}", message, status.value());
        return response.writeWith(
                Mono.just(response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8)))
        );
    }

    @Override
    public int getOrder() {
        // 로깅 필터보다 먼저 실행 (인증 실패 시 불필요한 로깅 방지)
        return -200;
    }

    /**
     * 경로 패턴 및 HTTP 메서드 제한
     */
    private record PathPattern(String path, HttpMethod method) {}
}

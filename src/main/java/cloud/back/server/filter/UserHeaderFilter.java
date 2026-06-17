package cloud.back.server.filter;

import cloud.back.server.security.GatewayServiceAuthenticationToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
@Slf4j
public class UserHeaderFilter implements GlobalFilter, Ordered {
    private static final List<String> INTERNAL_AUTH_HEADERS = List.of(
            "X-User-Name",
            "X-User-Key",
            "X-User-Role",
            "X-Gateway-Id",
            "X-Gateway-Timestamp",
            "X-Gateway-Nonce",
            "X-Gateway-Signature"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(context -> context.getAuthentication())
                .map(authentication -> {
                    if (authentication instanceof GatewayServiceAuthenticationToken gatewayAuthentication) {
                        String gatewayId = gatewayAuthentication.getGatewayId();
                        ServerHttpRequest request = sanitizedRequestBuilder(exchange)
                                .header("X-User-Name", URLEncoder.encode(gatewayId, StandardCharsets.UTF_8))
                                .header("X-User-Key", "gateway:" + gatewayId)
                                .header("X-User-Role", "GATEWAY")
                                .header("X-Gateway-Id", gatewayId)
                                .build();
                        return exchange.mutate().request(request).build();
                    }

                    if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
                        var jwt = jwtAuthenticationToken.getToken();
                        String username = jwt.getSubject();
                        Object userKeyClaim = jwt.getClaims().get("userKey");
                        String role = (String) jwt.getClaims().get("role");

                        String encodedUsername = username != null
                                ? URLEncoder.encode(username, StandardCharsets.UTF_8)
                                : "";

                        String userKey = resolveUserKey(userKeyClaim);

                        ServerHttpRequest mutatedRequest = sanitizedRequestBuilder(exchange)
                                .header("X-User-Name", encodedUsername)
                                .header("X-User-Key", userKey)
                                .header("X-User-Role", role != null ? role : "")
                                .build();

                        return exchange.mutate().request(mutatedRequest).build();
                    }

                    return exchange;
                })
                .defaultIfEmpty(exchange.mutate().request(sanitizeRequest(exchange)).build())
                .flatMap(chain::filter);
    }

    @Override
    public int getOrder() {
        return -50;
    }

    private String resolveUserKey(Object userKeyClaim) {
        if (userKeyClaim instanceof String value) {
            return value;
        }
        return "";
    }

    private ServerHttpRequest sanitizeRequest(ServerWebExchange exchange) {
        return sanitizedRequestBuilder(exchange).build();
    }

    private ServerHttpRequest.Builder sanitizedRequestBuilder(ServerWebExchange exchange) {
        return exchange.getRequest().mutate()
                .headers(headers -> INTERNAL_AUTH_HEADERS.forEach(headers::remove));
    }
}

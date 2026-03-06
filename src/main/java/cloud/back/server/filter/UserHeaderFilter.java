package cloud.back.server.filter;

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

@Component
@Slf4j
public class UserHeaderFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(context -> context.getAuthentication())
                .filter(auth -> auth instanceof JwtAuthenticationToken)
                .cast(JwtAuthenticationToken.class)
                .map(jwtAuth -> jwtAuth.getToken())
                .map(jwt -> {
                    String username = jwt.getSubject();
                    Object userKeyClaim = jwt.getClaims().get("userKey");
                    String role = (String) jwt.getClaims().get("role");

                    String encodedUsername = username != null
                            ? URLEncoder.encode(username, StandardCharsets.UTF_8)
                            : "";

                    String userKey = resolveUserKey(userKeyClaim);

                    ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                            .header("X-User-Name", encodedUsername)
                            .header("X-User-Key", userKey)
                            .header("X-User-Role", role != null ? role : "")
                            .build();

                    return exchange.mutate().request(mutatedRequest).build();
                })
                .defaultIfEmpty(exchange)
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
}

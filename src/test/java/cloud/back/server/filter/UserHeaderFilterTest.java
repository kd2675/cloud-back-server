package cloud.back.server.filter;

import cloud.back.server.security.GatewayServiceAuthenticationToken;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class UserHeaderFilterTest {

    private final UserHeaderFilter filter = new UserHeaderFilter();

    @Test
    void filter_unauthenticatedPublicRequest_removesSpoofedInternalHeaders() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/auth/login")
                .header("X-User-Key", "spoofed-user")
                .header("X-User-Role", "ADMIN")
                .header("X-Gateway-Id", "spoofed-gateway")
        );
        CapturingGatewayFilterChain chain = new CapturingGatewayFilterChain();

        filter.filter(exchange, chain).block();

        assertThat(chain.capturedExchange()).isNotNull();
        assertThat(chain.capturedExchange().getRequest().getHeaders().containsHeader("X-User-Key")).isFalse();
        assertThat(chain.capturedExchange().getRequest().getHeaders().containsHeader("X-User-Role")).isFalse();
        assertThat(chain.capturedExchange().getRequest().getHeaders().containsHeader("X-Gateway-Id")).isFalse();
    }

    @Test
    void filter_jwtAuthentication_replacesSpoofedHeadersWithVerifiedClaims() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/semo/v1/profile")
                .header("Authorization", "Bearer signed-access-token")
                .header("X-User-Key", "spoofed-user")
                .header("X-User-Role", "ADMIN")
        );
        CapturingGatewayFilterChain chain = new CapturingGatewayFilterChain();
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "HS512")
                .subject("verified-user")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(600))
                .claim("userKey", "verified-key")
                .claim("role", "USER")
                .build();

        filter.filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(new JwtAuthenticationToken(jwt)))
                .block();

        assertThat(chain.capturedExchange()).isNotNull();
        assertThat(chain.capturedExchange().getRequest().getHeaders().get("X-User-Key"))
                .isEqualTo(List.of("verified-key"));
        assertThat(chain.capturedExchange().getRequest().getHeaders().get("X-User-Role"))
                .isEqualTo(List.of("USER"));
        assertThat(chain.capturedExchange().getRequest().getHeaders().get("Authorization"))
                .isEqualTo(List.of("Bearer signed-access-token"));
    }

    @Test
    void filter_gatewayAuthentication_replacesSpoofedHeadersWithGatewayPrincipal() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/internal/zeroq/gateway/sensor/ingest/batch")
                .header("X-User-Key", "spoofed-user")
                .header("X-User-Role", "ADMIN")
                .header("X-Gateway-Signature", "incoming-signature")
                .header("X-Gateway-Content-SHA256", "incoming-hash")
        );
        CapturingGatewayFilterChain chain = new CapturingGatewayFilterChain();
        GatewayServiceAuthenticationToken authentication = GatewayServiceAuthenticationToken.authenticated(
                "GW-STORE-001",
                "POST",
                "/internal/zeroq/gateway/sensor/ingest/batch",
                "123",
                "nonce",
                "hash",
                "hash",
                "signature"
        );

        filter.filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
                .block();

        assertThat(chain.capturedExchange()).isNotNull();
        assertThat(chain.capturedExchange().getRequest().getHeaders().get("X-User-Key"))
                .isEqualTo(List.of("gateway:GW-STORE-001"));
        assertThat(chain.capturedExchange().getRequest().getHeaders().get("X-User-Role"))
                .isEqualTo(List.of("GATEWAY"));
        assertThat(chain.capturedExchange().getRequest().getHeaders().get("X-Gateway-Id"))
                .isEqualTo(List.of("GW-STORE-001"));
        assertThat(chain.capturedExchange().getRequest().getHeaders().containsHeader("X-Gateway-Signature")).isFalse();
        assertThat(chain.capturedExchange().getRequest().getHeaders().containsHeader("X-Gateway-Content-SHA256")).isFalse();
    }

    @Test
    void filter_stockBatchGatewayAuthentication_replacesSpoofedHeadersWithGatewayPrincipal() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/internal/stock-batch/v1/jobs/order-book-execution/run")
                .header("X-User-Key", "spoofed-user")
                .header("X-User-Role", "ADMIN")
                .header("X-Gateway-Signature", "incoming-signature")
                .header("X-Gateway-Content-SHA256", "incoming-hash")
        );
        CapturingGatewayFilterChain chain = new CapturingGatewayFilterChain();
        GatewayServiceAuthenticationToken authentication = GatewayServiceAuthenticationToken.authenticated(
                "stock-smoke-gateway",
                "POST",
                "/internal/stock-batch/v1/jobs/order-book-execution/run",
                "123",
                "nonce",
                "hash",
                "hash",
                "signature"
        );

        filter.filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
                .block();

        assertThat(chain.capturedExchange()).isNotNull();
        assertThat(chain.capturedExchange().getRequest().getHeaders().get("X-User-Key"))
                .isEqualTo(List.of("gateway:stock-smoke-gateway"));
        assertThat(chain.capturedExchange().getRequest().getHeaders().get("X-User-Role"))
                .isEqualTo(List.of("GATEWAY"));
        assertThat(chain.capturedExchange().getRequest().getHeaders().get("X-Gateway-Id"))
                .isEqualTo(List.of("stock-smoke-gateway"));
        assertThat(chain.capturedExchange().getRequest().getHeaders().containsHeader("X-Gateway-Signature")).isFalse();
        assertThat(chain.capturedExchange().getRequest().getHeaders().containsHeader("X-Gateway-Content-SHA256")).isFalse();
    }

    private static class CapturingGatewayFilterChain implements GatewayFilterChain {
        private final AtomicReference<ServerWebExchange> capturedExchange = new AtomicReference<>();

        @Override
        public Mono<Void> filter(ServerWebExchange exchange) {
            capturedExchange.set(exchange);
            return Mono.empty();
        }

        ServerWebExchange capturedExchange() {
            return capturedExchange.get();
        }
    }
}

package cloud.back.server.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class GatewayServiceAuthenticationConverter implements ServerAuthenticationConverter {
    public static final String GATEWAY_ID_HEADER = "X-Gateway-Id";
    public static final String TIMESTAMP_HEADER = "X-Gateway-Timestamp";
    public static final String NONCE_HEADER = "X-Gateway-Nonce";
    public static final String SIGNATURE_HEADER = "X-Gateway-Signature";

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        String gatewayId = exchange.getRequest().getHeaders().getFirst(GATEWAY_ID_HEADER);
        String timestamp = exchange.getRequest().getHeaders().getFirst(TIMESTAMP_HEADER);
        String nonce = exchange.getRequest().getHeaders().getFirst(NONCE_HEADER);
        String signature = exchange.getRequest().getHeaders().getFirst(SIGNATURE_HEADER);

        if (isBlank(gatewayId) || isBlank(timestamp) || isBlank(nonce) || isBlank(signature)) {
            return Mono.empty();
        }

        String method = exchange.getRequest().getMethod() == null
                ? ""
                : exchange.getRequest().getMethod().name();
        String requestPath = exchange.getRequest().getURI().getRawQuery() == null
                ? exchange.getRequest().getURI().getRawPath()
                : exchange.getRequest().getURI().getRawPath() + "?" + exchange.getRequest().getURI().getRawQuery();

        return Mono.just(new GatewayServiceAuthenticationToken(
                gatewayId,
                method,
                requestPath,
                timestamp,
                nonce,
                signature
        ));
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}

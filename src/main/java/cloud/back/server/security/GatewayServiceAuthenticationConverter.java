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
    public static final String CONTENT_SHA256_HEADER = "X-Gateway-Content-SHA256";
    public static final String SIGNATURE_HEADER = "X-Gateway-Signature";

    /**
     * 서명 헤더와 실제 요청 경로·본문 hash를 검증 전 토큰으로 변환한다.
     * 필수 헤더가 없으면 다른 인증 방식이 처리할 수 있도록 빈 결과를 반환한다.
     */
    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        String gatewayId = exchange.getRequest().getHeaders().getFirst(GATEWAY_ID_HEADER);
        String timestamp = exchange.getRequest().getHeaders().getFirst(TIMESTAMP_HEADER);
        String nonce = exchange.getRequest().getHeaders().getFirst(NONCE_HEADER);
        String contentSha256 = exchange.getRequest().getHeaders().getFirst(CONTENT_SHA256_HEADER);
        String signature = exchange.getRequest().getHeaders().getFirst(SIGNATURE_HEADER);
        String actualContentSha256 = exchange.getAttribute(GatewayRequestBodyHashFilter.CONTENT_SHA256_ATTRIBUTE);

        String requestPath = exchange.getRequest().getURI().getRawQuery() == null
                ? exchange.getRequest().getURI().getRawPath()
                : exchange.getRequest().getURI().getRawPath() + "?" + exchange.getRequest().getURI().getRawQuery();

        if (isBlank(gatewayId) || isBlank(timestamp) || isBlank(nonce) || isBlank(signature)) {
            return Mono.empty();
        }
        if (GatewayRequestBodyHashFilter.requiresBodyHash(requestPath)
                && (isBlank(contentSha256) || isBlank(actualContentSha256))) {
            return Mono.empty();
        }

        String method = exchange.getRequest().getMethod() == null
                ? ""
                : exchange.getRequest().getMethod().name();
        return Mono.just(new GatewayServiceAuthenticationToken(
                gatewayId,
                method,
                requestPath,
                timestamp,
                nonce,
                contentSha256,
                actualContentSha256,
                signature
        ));
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}

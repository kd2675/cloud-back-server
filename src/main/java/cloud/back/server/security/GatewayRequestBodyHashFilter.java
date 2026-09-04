package cloud.back.server.security;

import cloud.back.server.config.GatewayServiceAuthProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.HexFormat;

@Component
@RequiredArgsConstructor
public class GatewayRequestBodyHashFilter implements WebFilter, Ordered {
    public static final String CONTENT_SHA256_ATTRIBUTE =
            GatewayRequestBodyHashFilter.class.getName() + ".contentSha256";

    private final GatewayServiceAuthProperties authProperties;

    /**
     * 서명 대상 내부 요청 body를 제한 크기 안에서 한 번 읽어 SHA-256을 저장하고,
     * downstream에서도 다시 읽을 수 있도록 동일 바이트로 request body를 복원한다.
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (!requiresBodyHash(exchange.getRequest().getURI().getRawPath())) {
            return chain.filter(exchange);
        }

        return DataBufferUtils.join(
                        exchange.getRequest().getBody(),
                        authProperties.getMaxSignedBodyBytes()
                )
                .map(this::copyAndRelease)
                .defaultIfEmpty(new byte[0])
                .flatMap(body -> {
                    exchange.getAttributes().put(CONTENT_SHA256_ATTRIBUTE, sha256Hex(body));
                    ServerHttpRequest request = new ServerHttpRequestDecorator(exchange.getRequest()) {
                        @Override
                        public Flux<DataBuffer> getBody() {
                            return Flux.just(exchange.getResponse().bufferFactory().wrap(body));
                        }
                    };
                    return chain.filter(exchange.mutate().request(request).build());
                })
                .onErrorResume(DataBufferLimitException.class, error -> {
                    exchange.getResponse().setStatusCode(HttpStatus.CONTENT_TOO_LARGE);
                    return exchange.getResponse().setComplete();
                });
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    /** body hash 인증을 적용할 ZeroQ gateway 내부 경로인지 판정한다. */
    static boolean requiresBodyHash(String path) {
        return path != null && path.startsWith("/internal/zeroq/gateway/");
    }

    private byte[] copyAndRelease(DataBuffer dataBuffer) {
        try {
            byte[] body = new byte[dataBuffer.readableByteCount()];
            int offset = 0;
            try (DataBuffer.ByteBufferIterator iterator = dataBuffer.readableByteBuffers()) {
                while (iterator.hasNext()) {
                    ByteBuffer byteBuffer = iterator.next();
                    int length = byteBuffer.remaining();
                    byteBuffer.get(body, offset, length);
                    offset += length;
                }
            }
            return body;
        } finally {
            DataBufferUtils.release(dataBuffer);
        }
    }

    private String sha256Hex(byte[] body) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to hash gateway request body", ex);
        }
    }
}

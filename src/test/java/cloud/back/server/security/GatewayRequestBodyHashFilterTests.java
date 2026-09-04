package cloud.back.server.security;

import cloud.back.server.config.GatewayServiceAuthProperties;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class GatewayRequestBodyHashFilterTests {

    @Test
    void filter_gatewayPath_hashesAndRestoresRequestBody() {
        GatewayServiceAuthProperties properties = new GatewayServiceAuthProperties();
        properties.setMaxSignedBodyBytes(1024);
        GatewayRequestBodyHashFilter filter = new GatewayRequestBodyHashFilter(properties);
        String body = "{\"sensorId\":\"SPOT-014\"}";
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/internal/zeroq/gateway/sensor/ingest/batch").body(body)
        );
        AtomicReference<String> forwardedBody = new AtomicReference<>();

        filter.filter(exchange, filteredExchange -> DataBufferUtils.join(filteredExchange.getRequest().getBody())
                .doOnNext(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    int offset = 0;
                    try (org.springframework.core.io.buffer.DataBuffer.ByteBufferIterator iterator =
                                 dataBuffer.readableByteBuffers()) {
                        while (iterator.hasNext()) {
                            ByteBuffer byteBuffer = iterator.next();
                            int length = byteBuffer.remaining();
                            byteBuffer.get(bytes, offset, length);
                            offset += length;
                        }
                    }
                    DataBufferUtils.release(dataBuffer);
                    forwardedBody.set(new String(bytes, StandardCharsets.UTF_8));
                })
                .then()).block();

        assertThat(forwardedBody.get()).isEqualTo(body);
        assertThat((String) exchange.getAttribute(GatewayRequestBodyHashFilter.CONTENT_SHA256_ATTRIBUTE))
                .isEqualTo("b782ec8ccdce1005ab694b452be3218ac6bbcfe928c6451aed1f1064acbd4b45");
    }

    @Test
    void filter_gatewayPath_bodyExceedsLimit_returnsPayloadTooLarge() {
        GatewayServiceAuthProperties properties = new GatewayServiceAuthProperties();
        properties.setMaxSignedBodyBytes(4);
        GatewayRequestBodyHashFilter filter = new GatewayRequestBodyHashFilter(properties);
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/internal/zeroq/gateway/sensor/ingest/batch").body("12345")
        );
        AtomicBoolean chainCalled = new AtomicBoolean(false);

        filter.filter(exchange, filteredExchange -> {
            chainCalled.set(true);
            return filteredExchange.getResponse().setComplete();
        }).block();

        assertThat(chainCalled).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.CONTENT_TOO_LARGE);
    }
}

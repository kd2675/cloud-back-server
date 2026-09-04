package cloud.back.server.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

class GatewayServiceAuthenticationConverterTests {

    private final GatewayServiceAuthenticationConverter converter = new GatewayServiceAuthenticationConverter();

    @Test
    void convert_zeroqGatewayPathWithoutBodyHash_returnsEmpty() {
        MockServerWebExchange exchange = MockServerWebExchange.from(baseRequest(
                "/internal/zeroq/gateway/sensor/ingest/batch"
        ));

        assertThat(converter.convert(exchange).block()).isNull();
    }

    @Test
    void convert_stockBatchPathWithoutBodyHash_preservesLegacyContract() {
        MockServerWebExchange exchange = MockServerWebExchange.from(baseRequest(
                "/internal/stock-batch/v1/jobs/order-book-execution/run"
        ));

        GatewayServiceAuthenticationToken token = (GatewayServiceAuthenticationToken) converter.convert(exchange).block();

        assertThat(token).isNotNull();
        assertThat(token.getContentSha256()).isNull();
        assertThat(token.getActualContentSha256()).isNull();
    }

    private MockServerHttpRequest.BaseBuilder<?> baseRequest(String path) {
        return MockServerHttpRequest.post(path)
                .header(GatewayServiceAuthenticationConverter.GATEWAY_ID_HEADER, "service-01")
                .header(GatewayServiceAuthenticationConverter.TIMESTAMP_HEADER, "1788480000000")
                .header(GatewayServiceAuthenticationConverter.NONCE_HEADER, "nonce-01")
                .header(GatewayServiceAuthenticationConverter.SIGNATURE_HEADER, "signature");
    }
}

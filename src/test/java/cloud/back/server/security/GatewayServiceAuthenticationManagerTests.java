package cloud.back.server.security;

import cloud.back.server.config.GatewayServiceAuthProperties;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GatewayServiceAuthenticationManagerTests {

    @Test
    void authenticateShouldAcceptValidSignature() throws Exception {
        GatewayServiceAuthProperties properties = new GatewayServiceAuthProperties();
        properties.setSharedSecret("test-shared-secret");
        properties.setAllowedClockSkewSeconds(300);
        GatewayServiceAuthenticationManager manager = new GatewayServiceAuthenticationManager(properties);

        String gatewayId = "GW-STORE-001";
        String method = "POST";
        String path = "/internal/zeroq/gateway/sensor/ingest/gateway-heartbeat";
        String timestamp = String.valueOf(Instant.now().toEpochMilli());
        String nonce = UUID.randomUUID().toString();
        String signature = GatewayServiceAuthenticationManager.hmacHex(
                GatewayServiceAuthenticationManager.buildPayload(gatewayId, method, path, timestamp, nonce),
                properties.getSharedSecret()
        );

        GatewayServiceAuthenticationToken token = new GatewayServiceAuthenticationToken(
                gatewayId,
                method,
                path,
                timestamp,
                nonce,
                signature
        );

        var authentication = manager.authenticate(token).block();
        assertThat(authentication).isNotNull();
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getPrincipal()).isEqualTo(gatewayId);
    }

    @Test
    void authenticateShouldRejectInvalidSignature() {
        GatewayServiceAuthProperties properties = new GatewayServiceAuthProperties();
        properties.setSharedSecret("test-shared-secret");
        properties.setAllowedClockSkewSeconds(300);
        GatewayServiceAuthenticationManager manager = new GatewayServiceAuthenticationManager(properties);

        GatewayServiceAuthenticationToken token = new GatewayServiceAuthenticationToken(
                "GW-STORE-001",
                "POST",
                "/internal/zeroq/gateway/sensor/ingest/gateway-heartbeat",
                String.valueOf(Instant.now().toEpochMilli()),
                UUID.randomUUID().toString(),
                "invalid-signature"
        );

        assertThatThrownBy(() -> manager.authenticate(token).block())
                .isInstanceOf(Exception.class);
    }
}

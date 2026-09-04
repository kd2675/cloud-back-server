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
        assertValidSignatureForPath("/internal/zeroq/gateway/sensor/ingest/gateway-heartbeat");
    }

    @Test
    void authenticateShouldAcceptStockBatchJobPathSignature() throws Exception {
        GatewayServiceAuthProperties properties = new GatewayServiceAuthProperties();
        properties.setSharedSecret("test-shared-secret");
        properties.setAllowedClockSkewSeconds(300);
        GatewayServiceAuthenticationManager manager = new GatewayServiceAuthenticationManager(properties);

        String gatewayId = "STOCK-BATCH-01";
        String method = "POST";
        String path = "/internal/stock-batch/v1/jobs/order-book-execution/run";
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
                null,
                null,
                signature
        );

        assertThat(manager.authenticate(token).block()).isNotNull();
    }

    private void assertValidSignatureForPath(String path) throws Exception {
        GatewayServiceAuthProperties properties = new GatewayServiceAuthProperties();
        properties.setSharedSecret("test-shared-secret");
        properties.setAllowedClockSkewSeconds(300);
        GatewayServiceAuthenticationManager manager = new GatewayServiceAuthenticationManager(properties);

        String gatewayId = "GW-STORE-001";
        String method = "POST";
        String timestamp = String.valueOf(Instant.now().toEpochMilli());
        String nonce = UUID.randomUUID().toString();
        String contentSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        String signature = GatewayServiceAuthenticationManager.hmacHex(
                GatewayServiceAuthenticationManager.buildPayload(
                        gatewayId,
                        method,
                        path,
                        timestamp,
                        nonce,
                        contentSha256
                ),
                properties.getSharedSecret()
        );

        GatewayServiceAuthenticationToken token = new GatewayServiceAuthenticationToken(
                gatewayId,
                method,
                path,
                timestamp,
                nonce,
                contentSha256,
                contentSha256,
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
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "invalid-signature"
        );

        assertThatThrownBy(() -> manager.authenticate(token).block())
                .isInstanceOf(Exception.class);
    }

    @Test
    void authenticate_timestampSubtractionWouldOverflow_rejectsExpiredRequest() {
        GatewayServiceAuthProperties properties = new GatewayServiceAuthProperties();
        properties.setSharedSecret("test-shared-secret");
        properties.setAllowedClockSkewSeconds(300);
        GatewayServiceAuthenticationManager manager = new GatewayServiceAuthenticationManager(properties);

        GatewayServiceAuthenticationToken token = new GatewayServiceAuthenticationToken(
                "GW-STORE-001",
                "POST",
                "/internal/stock-batch/v1/jobs/order-book-execution/run",
                String.valueOf(Long.MIN_VALUE),
                UUID.randomUUID().toString(),
                null,
                null,
                "unused"
        );

        assertThatThrownBy(() -> manager.authenticate(token).block())
                .isInstanceOf(Exception.class)
                .hasMessageContaining("timestamp expired");
    }

    @Test
    void authenticateShouldRejectBodyHashMismatch() {
        GatewayServiceAuthProperties properties = new GatewayServiceAuthProperties();
        properties.setSharedSecret("test-shared-secret");
        GatewayServiceAuthenticationManager manager = new GatewayServiceAuthenticationManager(properties);

        GatewayServiceAuthenticationToken token = new GatewayServiceAuthenticationToken(
                "GW-STORE-001",
                "POST",
                "/internal/zeroq/gateway/sensor/ingest/telemetry",
                String.valueOf(Instant.now().toEpochMilli()),
                UUID.randomUUID().toString(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "unused"
        );

        assertThatThrownBy(() -> manager.authenticate(token).block())
                .isInstanceOf(Exception.class)
                .hasMessageContaining("body hash mismatch");
    }

    @Test
    void authenticateShouldUseGatewaySpecificSecretWhenConfigured() throws Exception {
        GatewayServiceAuthProperties properties = new GatewayServiceAuthProperties();
        properties.setSharedSecret("fallback-must-not-be-used");
        properties.setGatewaySecrets(java.util.Map.of("GW-STORE-001", "gateway-specific-secret"));
        GatewayServiceAuthenticationManager manager = new GatewayServiceAuthenticationManager(properties);

        String timestamp = String.valueOf(Instant.now().toEpochMilli());
        String nonce = UUID.randomUUID().toString();
        String contentSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        String payload = GatewayServiceAuthenticationManager.buildPayload(
                "GW-STORE-001",
                "GET",
                "/internal/zeroq/gateway/sensor/commands/sensor/S-1/pending?markAsSent=true",
                timestamp,
                nonce,
                contentSha256
        );
        GatewayServiceAuthenticationToken token = new GatewayServiceAuthenticationToken(
                "GW-STORE-001",
                "GET",
                "/internal/zeroq/gateway/sensor/commands/sensor/S-1/pending?markAsSent=true",
                timestamp,
                nonce,
                contentSha256,
                contentSha256,
                GatewayServiceAuthenticationManager.hmacHex(payload, "gateway-specific-secret")
        );

        assertThat(manager.authenticate(token).block()).isNotNull();
    }
}

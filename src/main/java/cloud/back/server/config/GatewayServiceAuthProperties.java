package cloud.back.server.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "gateway.auth")
public class GatewayServiceAuthProperties {
    private String sharedSecret;
    private Map<String, String> gatewaySecrets = new HashMap<>();
    private long allowedClockSkewSeconds = 300L;
    private int maxSignedBodyBytes = 5 * 1024 * 1024;

    public String resolveSecret(String gatewayId) {
        if (!gatewaySecrets.isEmpty()) {
            return gatewaySecrets.get(gatewayId);
        }
        return sharedSecret;
    }
}

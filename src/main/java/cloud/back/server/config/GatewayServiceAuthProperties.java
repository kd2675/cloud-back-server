package cloud.back.server.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "gateway.auth")
public class GatewayServiceAuthProperties {
    private String sharedSecret;
    private long allowedClockSkewSeconds = 300L;
}

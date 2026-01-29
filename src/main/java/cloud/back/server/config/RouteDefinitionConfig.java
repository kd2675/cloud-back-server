package cloud.back.server.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 라우팅 설정을 더 쉽게 관리하기 위한 설정 클래스
 * 나중에 application.yml에서 주입받을 수 있도록 만들어져 있습니다.
 */
@Component
@ConfigurationProperties(prefix = "gateway.routes")
@Getter
@Setter
public class RouteDefinitionConfig {

    private List<RouteDefinition> routes = new ArrayList<>();

    @Getter
    @Setter
    public static class RouteDefinition {
        private String id;                  // 라우트 ID
        private String path;                // 경로 (예: /auth/**, /api/users/**)
        private String uri;                 // 대상 서비스 URI (예: lb://auth-service)
        private String method;              // HTTP 메소드 (GET, POST, PUT, DELETE)
        private Integer stripPrefix;        // 경로에서 제거할 접두사 수
        private Boolean requiresAuth;       // 인증 필요 여부
        private List<String> roles;         // 필요한 역할

        @Override
        public String toString() {
            return String.format(
                    "RouteDefinition{id='%s', path='%s', uri='%s', method='%s'}",
                    id, path, uri, method
            );
        }
    }

    @Override
    public String toString() {
        return "RouteDefinitionConfig{" +
                "routes=" + routes +
                '}';
    }
}

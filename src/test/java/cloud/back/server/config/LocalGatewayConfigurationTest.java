package cloud.back.server.config;

import java.io.IOException;

import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.io.FileSystemResource;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LocalGatewayConfigurationTest {

    @Test
    void defaultProfile_withoutExplicitProfile_usesLocal() throws IOException {
        assertThat(loadEnvironment("").getProperty("spring.profiles.default")).isEqualTo("local");
    }

    @Test
    void localProfile_withoutExternalToken_usesStockBatchLocalToken() throws IOException {
        assertThat(loadEnvironment("local", "").getProperty("stock.batch.internal.token"))
                .isEqualTo("local-stock-batch-internal-token");
    }

    @Test
    void localProfile_withExternalToken_usesExplicitToken() throws IOException {
        MockEnvironment environment = loadEnvironment("local", "")
                .withProperty("STOCK_BATCH_INTERNAL_TOKEN", "test-explicit-internal-token");

        assertThat(environment.getProperty("stock.batch.internal.token"))
                .isEqualTo("test-explicit-internal-token");
    }

    @Test
    void localProfile_withDevelopmentToken_bindsToLoopback() throws IOException {
        assertThat(loadEnvironment("local", "").getProperty("server.address"))
                .isEqualTo("127.0.0.1");
    }

    @Test
    void baseConfiguration_withoutExternalToken_requiresExplicitToken() throws IOException {
        MockEnvironment environment = loadEnvironment("");

        assertThatThrownBy(() -> environment.getProperty("stock.batch.internal.token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("STOCK_BATCH_INTERNAL_TOKEN");
    }

    @Test
    void prodProfile_withoutExternalToken_requiresExplicitToken() throws IOException {
        MockEnvironment environment = loadEnvironment("prod", "");

        assertThatThrownBy(() -> environment.getProperty("stock.batch.internal.token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("STOCK_BATCH_INTERNAL_TOKEN");
    }

    // Load the real configuration, not src/test/resources/application.yml, which supplies a test token.
    // MockEnvironment keeps the developer's shell variables and .env secrets out of these checks.
    private MockEnvironment loadEnvironment(String... profiles) throws IOException {
        MockEnvironment environment = new MockEnvironment();
        YamlPropertySourceLoader loader = new YamlPropertySourceLoader();
        for (String profile : profiles) {
            String suffix = profile.isEmpty() ? "" : "-" + profile;
            for (var source : loader.load("application" + suffix,
                    new FileSystemResource("src/main/resources/application" + suffix + ".yml"))) {
                environment.getPropertySources().addLast(source);
            }
        }
        return environment;
    }
}

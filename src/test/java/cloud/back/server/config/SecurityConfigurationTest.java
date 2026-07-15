package cloud.back.server.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class SecurityConfigurationTest {

    private static final String TEST_JWT_SECRET = "test-secret-key-for-cloud-back-server-jwt-hs512-minimum-length-64-chars-1234567890";

    @LocalServerPort
    private int port;

    @jakarta.annotation.Resource
    private CorsConfigurationSource corsConfigurationSource;

    @jakarta.annotation.Resource
    private RouteLocator routeLocator;

    @Test
    void corsConfigurationSource_stockFrontendOrigin_isAllowed() {
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/")
                .header(HttpHeaders.ORIGIN, "http://localhost:3005"));

        CorsConfiguration configuration = corsConfigurationSource.getCorsConfiguration(exchange);

        assertThat(configuration).isNotNull();
        assertThat(configuration.getAllowedOrigins()).contains("http://localhost:3005");
    }

    @Test
    void stockMarketGet_withoutAuthorization_isNotRejectedBySecurity() {
        assertThat(getStatus("/api/stock/v1/system/status")).isNotIn(401, 403);
        assertThat(getStatus("/api/stock/v1/markets/instruments")).isNotIn(401, 403);
        assertThat(getStatus("/api/stock/v1/markets/prices")).isNotIn(401, 403);
        assertThat(getStatus("/api/stock/v1/markets/prices/005930/ticks")).isNotIn(401, 403);
        assertThat(getStatus("/api/stock/v1/markets/order-books/005930")).isNotIn(401, 403);
        assertThat(getStatus("/api/stock/v1/markets/rankings")).isNotIn(401, 403);
    }

    @Test
    void stockProtectedApi_withoutAuthorization_isRejectedBySecurity() {
        assertThat(getStatus("/api/stock/v1/users/me")).isEqualTo(401);
        assertThat(getStatus("/api/stock/v1/accounts/me")).isEqualTo(401);
        assertThat(getStatus("/api/stock/v1/portfolio/me")).isEqualTo(401);
        assertThat(getStatus("/api/stock/v1/portfolio/me/snapshots")).isEqualTo(401);
        assertThat(getStatus("/api/stock/v1/holdings")).isEqualTo(401);
        assertThat(getStatus("/api/stock/v1/orders")).isEqualTo(401);
        assertThat(postStatus("/api/stock/v1/orders")).isEqualTo(401);
        assertThat(deleteStatus("/api/stock/v1/orders/1")).isEqualTo(401);
        assertThat(getStatus("/api/stock/v1/executions")).isEqualTo(401);
    }

    @Test
    void stockProtectedApi_withWrongServiceAudience_isRejectedBySecurity() throws Exception {
        assertThat(getStatus("/api/stock/v1/users/me", token("muse-api"))).isEqualTo(401);
    }

    @Test
    void stockProtectedApi_withStockAudience_passesSecurityBoundary() throws Exception {
        assertThat(getStatus("/api/stock/v1/users/me", token("stock-api"))).isNotIn(401, 403);
    }

    @Test
    void stockProtectedApi_withoutApiScope_isRejectedBySecurity() throws Exception {
        assertThat(getStatus("/api/stock/v1/users/me", token("stock-api", "profile"))).isEqualTo(401);
    }

    @Test
    void stockBatchJobApi_withoutGatewayAuthorization_isRejectedBySecurity() {
        assertThat(getStatus("/internal/stock-batch/v1/jobs/runtime-controls")).isEqualTo(401);
        assertThat(postStatus("/internal/stock-batch/v1/jobs/market-data/refresh")).isEqualTo(401);
        assertThat(postStatus("/internal/stock-batch/v1/jobs/order-book-execution/run")).isEqualTo(401);
        assertThat(postStatus("/internal/stock-batch/v1/jobs/portfolio-settlement/run")).isEqualTo(401);
        assertThat(patchStatus("/internal/stock-batch/v1/jobs/runtime-controls/auto-market")).isEqualTo(401);
    }

    @Test
    void userSignupPost_withoutAuthorization_isNotRejectedBySecurity() {
        assertThat(postStatus("/api/users")).isNotIn(401, 403);
    }

    @Test
    void authAndOAuthEndpoints_withoutAuthorization_areNotRejectedBySecurity() {
        assertThat(postStatus("/auth/login")).isNotIn(401, 403);
        assertThat(postStatus("/auth/refresh")).isNotIn(401, 403);
        assertThat(getStatus("/oauth2/authorize/naver-stock")).isNotIn(401, 403);
        assertThat(getStatus("/oauth2/authorize/kakao-stock")).isNotIn(401, 403);
        assertThat(getStatus("/login/oauth2/code/naver-stock")).isNotIn(401, 403);
        assertThat(getStatus("/login/oauth2/code/kakao-stock")).isNotIn(401, 403);
    }

    @Test
    void routeLocator_authApi_routesToAuthBackService() {
        assertAuthRoute("auth-login", HttpMethod.POST, "/auth/login");
        assertAuthRoute("auth-refresh", HttpMethod.POST, "/auth/refresh");
        assertAuthRoute("auth-logout", HttpMethod.POST, "/auth/logout");
        assertAuthRoute("auth-validate", HttpMethod.POST, "/auth/validate");
    }

    @Test
    void routeLocator_stockOAuth_routesToAuthBackService() {
        assertAuthRoute("auth-oauth2", HttpMethod.GET, "/oauth2/authorize/naver-stock");
        assertAuthRoute("auth-oauth2", HttpMethod.GET, "/oauth2/authorize/kakao-stock");
        assertAuthRoute("auth-oauth2-login-callback", HttpMethod.GET, "/login/oauth2/code/naver-stock");
        assertAuthRoute("auth-oauth2-login-callback", HttpMethod.GET, "/login/oauth2/code/kakao-stock");
    }

    @Test
    void routeLocator_stockApi_routesToStockBackService() {
        var stockRoute = routeLocator.getRoutes()
                .filter(route -> route.getId().equals("stock-back-service-api"))
                .single()
                .block();

        assertThat(stockRoute).isNotNull();
        assertThat(stockRoute.getUri().toString()).isEqualTo("lb://stock-back-service");
        assertThat(routeMatches(stockRoute, HttpMethod.GET, "/api/stock/v1/system/status")).isTrue();
        assertThat(routeMatches(stockRoute, HttpMethod.GET, "/api/stock/v1/markets/instruments")).isTrue();
        assertThat(routeMatches(stockRoute, HttpMethod.GET, "/api/stock/v1/markets/prices")).isTrue();
        assertThat(routeMatches(stockRoute, HttpMethod.GET, "/api/stock/v1/markets/prices/005930/ticks")).isTrue();
        assertThat(routeMatches(stockRoute, HttpMethod.GET, "/api/stock/v1/markets/order-books/005930")).isTrue();
        assertThat(routeMatches(stockRoute, HttpMethod.GET, "/api/stock/v1/markets/rankings")).isTrue();
        assertThat(routeMatches(stockRoute, HttpMethod.GET, "/api/stock/v1/users/me")).isTrue();
        assertThat(routeMatches(stockRoute, HttpMethod.GET, "/api/stock/v1/accounts/me")).isTrue();
        assertThat(routeMatches(stockRoute, HttpMethod.GET, "/api/stock/v1/portfolio/me")).isTrue();
        assertThat(routeMatches(stockRoute, HttpMethod.GET, "/api/stock/v1/portfolio/me/snapshots")).isTrue();
        assertThat(routeMatches(stockRoute, HttpMethod.GET, "/api/stock/v1/holdings")).isTrue();
        assertThat(routeMatches(stockRoute, HttpMethod.GET, "/api/stock/v1/orders")).isTrue();
        assertThat(routeMatches(stockRoute, HttpMethod.POST, "/api/stock/v1/orders")).isTrue();
        assertThat(routeMatches(stockRoute, HttpMethod.DELETE, "/api/stock/v1/orders/1")).isTrue();
        assertThat(routeMatches(stockRoute, HttpMethod.GET, "/api/stock/v1/executions")).isTrue();
    }

    @Test
    void routeLocator_stockBatchJobs_routesToStockBatchService() {
        var stockBatchRoute = routeLocator.getRoutes()
                .filter(route -> route.getId().equals("stock-batch-internal-jobs"))
                .single()
                .block();

        assertThat(stockBatchRoute).isNotNull();
        assertThat(stockBatchRoute.getUri().toString()).isEqualTo("lb://stock-batch-service");
        assertThat(routeMatches(stockBatchRoute, HttpMethod.GET, "/internal/stock-batch/v1/jobs/runtime-controls")).isTrue();
        assertThat(routeMatches(stockBatchRoute, HttpMethod.GET, "/internal/stock-batch/v1/jobs/auto-participant-cash-flow/status")).isTrue();
        assertThat(routeMatches(stockBatchRoute, HttpMethod.POST, "/internal/stock-batch/v1/jobs/market-data/refresh")).isTrue();
        assertThat(routeMatches(stockBatchRoute, HttpMethod.POST, "/internal/stock-batch/v1/jobs/order-book-execution/run")).isTrue();
        assertThat(routeMatches(stockBatchRoute, HttpMethod.POST, "/internal/stock-batch/v1/jobs/portfolio-settlement/run")).isTrue();
        assertThat(routeMatches(stockBatchRoute, HttpMethod.POST, "/internal/stock-batch/v1/jobs/auto-participant-cash-flow/run")).isTrue();
        assertThat(routeMatches(stockBatchRoute, HttpMethod.POST, "/internal/stock-batch/v1/jobs/unknown")).isTrue();
        assertThat(routeMatches(stockBatchRoute, HttpMethod.PATCH, "/internal/stock-batch/v1/jobs/runtime-controls/auto-market")).isTrue();
        assertThat(routeMatches(stockBatchRoute, HttpMethod.PATCH, "/internal/stock-batch/v1/jobs/auto-participant-cash-flow/status")).isTrue();
        assertThat(routeMatches(stockBatchRoute, HttpMethod.DELETE, "/internal/stock-batch/v1/jobs/order-book-execution/run")).isFalse();
        assertThat(routeMatches(stockBatchRoute, HttpMethod.GET, "/internal/stock-batch/v1/system/status")).isFalse();
    }

    @Test
    void routeLocator_userApi_routesRootAndNestedPathsToAuthBackService() {
        var userRoute = routeLocator.getRoutes()
                .filter(route -> route.getId().equals("user-api-all"))
                .single()
                .block();

        assertThat(userRoute).isNotNull();
        assertThat(userRoute.getUri().toString()).isEqualTo("lb://auth-back-server");
        assertThat(routeMatches(userRoute, "/api/users")).isTrue();
        assertThat(routeMatches(userRoute, "/api/users/me")).isTrue();
    }

    private void assertAuthRoute(String routeId, HttpMethod method, String uri) {
        var route = routeLocator.getRoutes()
                .filter(candidate -> candidate.getId().equals(routeId))
                .single()
                .block();

        assertThat(route).isNotNull();
        assertThat(route.getUri().toString()).isEqualTo("lb://auth-back-server");
        assertThat(routeMatches(route, method, uri)).isTrue();
    }

    private int getStatus(String uri) {
        return WebClient.create("http://localhost:" + port)
                .get()
                .uri(uri)
                .exchangeToMono(response -> reactor.core.publisher.Mono.just(response.statusCode().value()))
                .block();
    }

    private int getStatus(String uri, String token) {
        return WebClient.create("http://localhost:" + port)
                .get()
                .uri(uri)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchangeToMono(response -> reactor.core.publisher.Mono.just(response.statusCode().value()))
                .block();
    }

    private String token(String audience) throws Exception {
        return token(audience, "api");
    }

    private String token(String audience, String scope) throws Exception {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader(JWSAlgorithm.HS512),
                new JWTClaimsSet.Builder()
                        .subject("test-user")
                        .issuer("http://localhost:9000")
                        .audience(audience)
                        .issueTime(new Date())
                        .expirationTime(new Date(System.currentTimeMillis() + 60_000))
                        .claim("scope", scope)
                        .build()
        );
        jwt.sign(new MACSigner(TEST_JWT_SECRET));
        return jwt.serialize();
    }

    private int postStatus(String uri) {
        return WebClient.create("http://localhost:" + port)
                .post()
                .uri(uri)
                .exchangeToMono(response -> reactor.core.publisher.Mono.just(response.statusCode().value()))
                .block();
    }

    private int deleteStatus(String uri) {
        return WebClient.create("http://localhost:" + port)
                .delete()
                .uri(uri)
                .exchangeToMono(response -> reactor.core.publisher.Mono.just(response.statusCode().value()))
                .block();
    }

    private int patchStatus(String uri) {
        return WebClient.create("http://localhost:" + port)
                .patch()
                .uri(uri)
                .exchangeToMono(response -> reactor.core.publisher.Mono.just(response.statusCode().value()))
                .block();
    }

    private boolean routeMatches(org.springframework.cloud.gateway.route.Route route, String uri) {
        return routeMatches(route, HttpMethod.POST, uri);
    }

    private boolean routeMatches(org.springframework.cloud.gateway.route.Route route, HttpMethod method, String uri) {
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.method(method, uri).build());
        return reactor.core.publisher.Mono.from(route.getPredicate().apply(exchange)).block();
    }
}

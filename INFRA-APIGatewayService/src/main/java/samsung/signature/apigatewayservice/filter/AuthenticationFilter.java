package samsung.signature.apigatewayservice.filter;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import samsung.signature.apigatewayservice.jwt.JwtProvider;

@Slf4j
@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {
	// 제외할 경로 목록
	private static final List<String> EXCLUDED_PATHS = Arrays.asList(
		"/members/validate",
		"/members",
		"/members/signin"
	);
	private static final String DEVICE_ID = "UID";
	private final JwtProvider jwtProvider;

	public AuthenticationFilter(final JwtProvider jwtProvider) {
		super(Config.class);
		this.jwtProvider = jwtProvider;
	}

	@Override
	public GatewayFilter apply(Config config) {
		return ((exchange, chain) -> {
			ServerHttpRequest request = exchange.getRequest();

			log.info("Global PRE baseMessage : {}", config.getBaseMessage());

			if (config.isPreLogger()) {
				log.info("Global Filter Start : request id = {}", request.getId());
			}

			String path = request.getPath().toString();

			// 특정 경로일 때 필터를 건너뛰도록 조건 추가
			if (skipFilter(path)) {
				return chain.filter(exchange);
			}

			HttpHeaders headers = request.getHeaders();

			// Authorization 헤더가 없을 경우
			if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
				return onError(exchange, "로그인 세션이 만료되었습니다.");
			}
			// 기기정보가 담긴 UID 헤더가 없을 경우
			if (!headers.containsKey("UID")) {
				return onError(exchange, "로그인한 기기정보가 없습니다.");
			}

			// UID 추출 및 검증
			String UID = Objects.requireNonNull(headers.getFirst(DEVICE_ID));

			// JWT 토큰 추출
			String jwtToken = headers
				.getFirst(HttpHeaders.AUTHORIZATION)
				.replace("Bearer ", "");

			// JWT 토큰 검증
			return jwtProvider.decodeAccessToken(jwtToken, UID)
				.map(attr -> {
					addAuthorizationHeaders(request, attr);
					return chain.filter(exchange);
				})
				.orElseGet(() ->
					onError(exchange, "로그인 세션이 만료되었습니다.")
				);
		});
	}

	private Mono<Void> onError(ServerWebExchange exchange, String err) {
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(HttpStatus.UNAUTHORIZED);
		return response.setComplete();
	}

	private void addAuthorizationHeaders(
		final ServerHttpRequest request,
		final Map<String, String> attr
	) {
		request.mutate()
			.headers(httpHeaders -> attr.forEach(httpHeaders::set))
			.build();
	}

	private boolean skipFilter(final String path) {
		return path.startsWith("/auth-service") && EXCLUDED_PATHS.stream().anyMatch(path::endsWith);
	}

	@Data
	public static class Config {
		private String baseMessage;
		private boolean preLogger;
		private boolean postLogger;
	}
}

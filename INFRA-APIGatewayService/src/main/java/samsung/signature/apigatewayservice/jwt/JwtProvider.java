package samsung.signature.apigatewayservice.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtProvider {
	private static final String MEMBER_ID = "Member-Id";
	private static final String ACCESS_TOKEN = "Access-Token";
	private static final String ACCESS_EXPIRED_TIME = "Access-Expired-Time";
	private final RedisTemplate<byte[], byte[]> redisTemplate;
	private final Key key;

	public JwtProvider(
		@Value(value = "${jwt.secret-key}") String secretKey,
		RedisTemplate<byte[], byte[]> redisTemplate
	) {
		this.redisTemplate = redisTemplate;
		byte[] keyBytes = Decoders.BASE64.decode(secretKey);
		this.key = Keys.hmacShaKeyFor(keyBytes);
	}

	public Optional<Map<String, String>> decodeAccessToken(final String token, final String UID) {
		return isAccessTokenInBlackList(token) ?
			Optional.empty() : generateAuthorizationInfo(token, UID);
	}

	private Optional<Map<String, String>> generateAuthorizationInfo(final String token, final String UID) {
		return parseToken(token)
			.flatMap(claims -> {
				if (isValidToken(claims, UID)) {
					Map<String, String> attr = new HashMap<>();
					attr.put(MEMBER_ID, claims.getSubject());
					attr.put(ACCESS_TOKEN, token);
					attr.put(ACCESS_EXPIRED_TIME, String.valueOf(
						claims.getExpiration().getTime() - System.currentTimeMillis())
					);
					return Optional.of(attr);
				}
				return Optional.empty();
			});
	}

	private boolean isAccessTokenInBlackList(String jwtToken) {
		return Boolean.TRUE.equals(redisTemplate.hasKey(jwtToken.getBytes(StandardCharsets.UTF_8)));
	}

	private boolean isValidToken(final Claims claims, final String UID) {
		if (ObjectUtils.isEmpty(claims.get("uid")) || !UID.equals(claims.get("uid"))) {
			log.info("Not equals UID and JWT Token");
			return false;
		}
		return true;
	}

	private Optional<Claims> parseToken(String token) {
		try {
			return Optional.of(Jwts
				.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(token)
				.getBody());
		} catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
			log.info("Invalid JWT Token", e);
		} catch (ExpiredJwtException e) {
			log.info("Expired JWT Token", e);
		} catch (UnsupportedJwtException e) {
			log.info("Unsupported JWT Token", e);
		} catch (IllegalArgumentException e) {
			log.info("JWT claims string is empty.", e);
		}
		return Optional.empty();
	}
}

package pro.gravit.launchserver.helper;

import io.jsonwebtoken.Jwts;
import pro.gravit.launchserver.auth.core.User;
import pro.gravit.utils.helper.SecurityHelper;

import java.security.MessageDigest;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.UUID;

public class LegacySessionHelper {
    public static String makeAccessJwtTokenFromString(User user, LocalDateTime expirationTime, ECPrivateKey privateKey) {
        return Jwts.builder()
                .setIssuer("LaunchServer")
                .setSubject(user.getUsername())
                .claim("uuid", user.getUUID().toString())
                .claim("permissions", user.getPermissions().getPerms())
                .setExpiration(Date.from(expirationTime
                        .toInstant(ZoneOffset.UTC)))
                .signWith(privateKey)
                .compact();
    }

    public static JwtTokenInfo getJwtInfoFromAccessToken(String token, ECPublicKey publicKey) {
        var parser = Jwts.parser()
                .requireIssuer("LaunchServer")
                .clock(() -> new Date(Clock.systemUTC().millis()))
                .verifyWith(publicKey)
                .build();
        var claims = parser.parseSignedClaims(token);
        var uuid = UUID.fromString(claims.getPayload().get("uuid", String.class));
        var username = claims.getPayload().getSubject();
        return new JwtTokenInfo(username, uuid);
    }

    public static String makeRefreshTokenFromPassword(String username, String rawPassword, String secretSalt) {
        if (rawPassword == null) {
            rawPassword = "";
        }
        long timestamp = System.currentTimeMillis();
        String nonce = SecurityHelper.toHex(SecurityHelper.randomBytes(8));
        String hash = SecurityHelper.toHex(SecurityHelper.digest(SecurityHelper.DigestAlgorithm.SHA256,
                "%s.%s.%s.%s.%s.%s".formatted(secretSalt, username, rawPassword, secretSalt, timestamp, nonce)));
        return "%d.%s.%s".formatted(timestamp, nonce, hash);
    }

    public static boolean verifyRefreshToken(String tokenPayload, String username, String rawPassword, String secretSalt, long maxAgeMillis) {
        String[] parts = tokenPayload.split("\\.", 3);
        if (parts.length != 3) return false;
        try {
            long timestamp = Long.parseLong(parts[0]);
            if (System.currentTimeMillis() - timestamp > maxAgeMillis) return false;
            String nonce = parts[1];
            if (rawPassword == null) rawPassword = "";
            String expectedHash = SecurityHelper.toHex(SecurityHelper.digest(SecurityHelper.DigestAlgorithm.SHA256,
                    "%s.%s.%s.%s.%s.%s".formatted(secretSalt, username, rawPassword, secretSalt, timestamp, nonce)));
            return MessageDigest.isEqual(expectedHash.getBytes(), parts[2].getBytes());
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public record JwtTokenInfo(String username, UUID uuid) {
    }
}

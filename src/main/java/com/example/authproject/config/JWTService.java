package com.example.authproject.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JWTService {

    /* Minimun accepted by JWT is an 256-bit key
    https://generate-random.org/encryption-key-generator?count=1&bytes=256&cipher=aes-256-cbc-hmac-sha256&string=&password=
    */
    private static final String SECRET_KEY = "64pngZ5O5LM2CA469jPFJaj2oUA3Xtvdcix+4/nUpoDhbWNjeGFaY+y0cAgtVTNNo2IxhnwOPV/K0zG48e3Ii0ZXZsiAtw/Qx82lh0MRIoLkj1YNS2jxNOo6XUtZTMeVtXw/U9WGw8kKWzwQEKkJIbaVzOsxmSq5dKIlao8oiuZtg+nv1gQyRrkmwyPjeqXjij9Bl8x//Cea7rRZQ0/HqEbkLEzf0GJe4lczaYTaHvhkOHKsVTExevmjDdYqN07Bxniztl7VlMVQHHUVAcHy+5xZcnkyrUZI5tvScL3WMvoW4hWkoLMIlzDaZ9IazhonJUls06FuaUKF60d09B+6qXDTY2e6HV/dFaOwHUJg4as=";

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);

    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // generate from user details
    public String generateTokenFromUser(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder().setClaims(extraClaims).setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 4))
                .signWith(getSignInKey(), SignatureAlgorithm.ES256)
                .compact();
    }

    // Check token from user
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(getSignInKey())
                .build().parseClaimsJws(token).getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}

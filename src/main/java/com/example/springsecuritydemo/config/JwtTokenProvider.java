package com.example.springsecuritydemo.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final UserDetailsService userDetailsService;

    private final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static long validityInMilliseconds = 3600000; // 1h

    public String getUsernameFromToken(String token) {
        Jws<Claims> claimsJws = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
        return claimsJws.getBody().getSubject();
    }

    public String createToken(Authentication authentication) {
        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();
        Instant now = Instant.now();
        Instant expiryDate = now.plus(validityInMilliseconds, ChronoUnit.MILLIS);
        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiryDate))
                .signWith(key)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return !claimsJws.getBody().getExpiration().before(new Date(0));
        } catch (Exception e) {
            return false;
        }
    }

    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public Optional<UsernamePasswordAuthenticationToken> get(final HttpServletRequest httpRequest) {
        try {

            // Try to retrieve token from Authentication Header of HttpServletRequest
            // Optional<String> jwtTokenOptional =
            // jwtTokenFromAuthHeaderExtractor.extract(httpRequest);
            // if (jwtTokenOptional.isEmpty()) {
            // return Optional.empty();
            // }

            // Validate jwtToken
            final String jwtToken = resolveToken(httpRequest);
            if (validateToken(jwtToken)) {
                return Optional.empty();
            }

            // // Try to retrieve userEmail from jwtToken
            final String userPhone = getUsernameFromToken(jwtToken);
            if (userPhone == null ||
                    SecurityContextHolder.getContext().getAuthentication() != null) {
                return Optional.empty();
            }

            // // Try to retrieve userDetails from system
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userPhone);

            // Create authToken
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null,
                    userDetails.getAuthorities());

            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpRequest));

            return Optional.of(authToken);
        } catch (Exception exception) {
            // log.error("Jwt token validation error", exception);
            throw new JwtTokenException(exception);
        }
    }
}

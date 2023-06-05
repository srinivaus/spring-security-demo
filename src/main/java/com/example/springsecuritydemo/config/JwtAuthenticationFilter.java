package com.example.springsecuritydemo.config;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(@NonNull final HttpServletRequest httpRequest,
            @NonNull final HttpServletResponse httpResponse,
            @NonNull final FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (null != authentication) {
            Optional<UsernamePasswordAuthenticationToken> authenticationTokenOptional = jwtTokenProvider
                    .get(httpRequest);

            if (authenticationTokenOptional.isPresent()) {
                UsernamePasswordAuthenticationToken authenticationToken = authenticationTokenOptional.get();
                SecurityContextHolder
                        .getContext()
                        .setAuthentication(authenticationToken);
            }
        }

        filterChain.doFilter(httpRequest, httpResponse);
    }
}
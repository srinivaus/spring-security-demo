package com.example.springsecuritydemo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties.User;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration {
    private static final String API_AUTH_URL_PREFIX = "/login/sendOtp";
    public static final String ACTUATOR_ENDPOINTS_URL_PREFIX = "/dev/**";
    @Autowired
   private final JwtAuthenticationFilter jwtTokenFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity httpSecurity) throws Exception {
       /* httpSecurity
                .csrf().disable()
                .authorizeHttpRequests()
                .requestMatchers("/login/sendOtp").permitAll()
                // .requestMatchers(ACTUATOR_ENDPOINTS_URL_PREFIX).permitAll()
                .anyRequest().authenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                ;*/
        httpSecurity.csrf().disable().authorizeHttpRequests().requestMatchers("/dev/login/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .addFilterAfter(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
               // .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }
}
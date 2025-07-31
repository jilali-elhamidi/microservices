package com.example.auth_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer; // Import pour Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.HeaderWriter; // Import pour HeaderWriter
import org.springframework.security.web.header.writers.StaticHeadersWriter; // Import pour StaticHeadersWriter

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                "/auth/register",
                                "/auth/login",
                                "/auth/validateToken",
                                "/auth/refresh-token",
                                "/auth/2fa/**",
                                "/login-success",
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .defaultSuccessUrl("/login-success", true)
                )
                // AJOUT DE LA CONFIGURATION DES EN-TÊTES DE SÉCURITÉ HTTP
                .headers(headers -> headers
                        .xssProtection(Customizer.withDefaults()) // X-XSS-Protection
                        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;")) // CSP
                        .frameOptions(frameOptions -> frameOptions.deny()) // X-Frame-Options: DENY
                        .addHeaderWriter(new StaticHeadersWriter("X-Content-Type-Options", "nosniff")) // X-Content-Type-Options
                        .addHeaderWriter(new StaticHeadersWriter("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")) // HSTS
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

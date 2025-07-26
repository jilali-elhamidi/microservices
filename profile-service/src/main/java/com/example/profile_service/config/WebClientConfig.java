package com.example.profile_service.config;

import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    @Bean
    @LoadBalanced // Permet d'utiliser le nom du service (ex: http://auth-service)
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }
}
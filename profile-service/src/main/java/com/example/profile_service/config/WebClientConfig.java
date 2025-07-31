package com.example.profile_service.config;

import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

@Configuration
public class WebClientConfig {

    @Bean
    @LoadBalanced
    public WebClient.Builder loadBalancedWebClientBuilder() {
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(customHttpClient()));
    }

    @Bean
    public WebClient authWebClient(WebClient.Builder builder) {
        return builder
                .baseUrl("https://auth-service")  // Nom Eureka
                .build();
    }

    private HttpClient customHttpClient() {
        try {
            var sslContext = SslContextBuilder
                    .forClient()
                    .trustManager(InsecureTrustManagerFactory.INSTANCE)
                    .build();

            return HttpClient.create()
                    .secure(t -> t.sslContext(sslContext));
        } catch (Exception e) {
            throw new RuntimeException("Failed to create custom HttpClient", e);
        }
    }
}

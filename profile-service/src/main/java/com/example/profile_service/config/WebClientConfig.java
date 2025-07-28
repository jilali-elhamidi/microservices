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
    public WebClient authWebClient() {
        try {
            var sslContext = SslContextBuilder.forClient()
                    .trustManager(InsecureTrustManagerFactory.INSTANCE)
                    .build();

            var httpClient = HttpClient.create()
                    .secure(t -> t.sslContext(sslContext));

            return WebClient.builder()
                    .baseUrl("https://192.168.56.1:8443") // ← IP directe
                    .clientConnector(new ReactorClientHttpConnector(httpClient))
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create WebClient", e);
        }
    }
}
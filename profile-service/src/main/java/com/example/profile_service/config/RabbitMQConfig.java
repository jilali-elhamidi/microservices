package com.example.profile_service.config;

import org.springframework.amqp.core.Queue;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitMQConfig {

    // Nom de la file d'attente que le profile-service écoute
    public static final String QUEUE_NAME = "user_registration_queue";

    @Bean
    public Queue userRegistrationQueue() {
        // Déclare la file d'attente pour s'assurer qu'elle existe sur RabbitMQ
        return new Queue(QUEUE_NAME, true); // 'true' rend la file durable
    }

    @Bean
    public MessageConverter jsonMessageConverter() {
        // Configure le convertisseur de messages JSON, nécessaire pour la désérialisation
        return new Jackson2JsonMessageConverter();
    }
}

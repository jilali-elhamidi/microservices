package com.example.auth_service.service;

import com.example.auth_service.config.RabbitMQConfig;
import com.example.auth_service.dto.RegisterRequest;
import com.example.auth_service.event.UserRegisteredEvent;
import com.example.auth_service.model.User;
import com.example.auth_service.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class UserRegistrationService {

    private static final Logger log = LoggerFactory.getLogger(UserRegistrationService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RabbitTemplate rabbitTemplate;

    public UserRegistrationService(UserRepository userRepository, PasswordEncoder passwordEncoder, RabbitTemplate rabbitTemplate) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.rabbitTemplate = rabbitTemplate;
    }


    public User registerNewUser(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("Email already exists");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.set2faEnabled(false);
        user.setFailedLoginAttempts(0);
        user.setAccountLocked(false);
        User savedUser = userRepository.save(user);

        publishUserRegisteredEvent(savedUser.getId(), savedUser.getEmail());
        log.info("UTILISATEUR_ENREGISTRE: User registered successfully: {}", user.getEmail());
        return savedUser;
    }

    private void publishUserRegisteredEvent(UUID userId, String email) {
        UserRegisteredEvent event = new UserRegisteredEvent();
        event.setUserId(userId);
        event.setEmail(email);

        log.info("RABBITMQ_ENVOI_TENTATIVE: Attempting to send UserRegisteredEvent for userId: {} to queue: {}", userId, RabbitMQConfig.QUEUE_NAME);
        try {
            rabbitTemplate.convertAndSend(RabbitMQConfig.QUEUE_NAME, event);
            log.info("RABBITMQ_ENVOI_SUCCES: Successfully sent UserRegisteredEvent for userId: {}", userId);
        } catch (Exception e) {
            log.error("RABBITMQ_ENVOI_ECHEC: Failed to send UserRegisteredEvent for userId: {}", userId, e);
        }
    }
}

package com.example.auth_service.service;

import com.example.auth_service.config.RabbitMQConfig;
import com.example.auth_service.event.UserRegisteredEvent;
import com.example.auth_service.model.User;
import com.example.auth_service.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
public class OAuth2UserManagementService {

    private static final Logger log = LoggerFactory.getLogger(OAuth2UserManagementService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RabbitTemplate rabbitTemplate;

    public OAuth2UserManagementService(UserRepository userRepository, PasswordEncoder passwordEncoder, RabbitTemplate rabbitTemplate) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.rabbitTemplate = rabbitTemplate;
    }

    public UUID findOrCreateOAuth2User(String email, String name) {
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            log.info("OAUTH2_CONNEXION: Existing user logged in via OAuth2: {}", email);
            return userOptional.get().getId();
        } else {
            User newUser = new User();
            newUser.setEmail(email);
            // Pour les utilisateurs OAuth2, ils n'ont pas de mot de passe direct.
            // Si vous voulez qu'ils puissent se connecter par mot de passe plus tard,
            // vous devrez leur permettre de définir un mot de passe après l'inscription OAuth2.
            newUser.setPassword(passwordEncoder.encode(UUID.randomUUID().toString())); // Mot de passe aléatoire, mais inutilisable par l'utilisateur
            newUser.set2faEnabled(false);
            newUser.setFailedLoginAttempts(0);
            newUser.setAccountLocked(false);
            User savedUser = userRepository.save(newUser);

            publishUserRegisteredEvent(savedUser.getId(), savedUser.getEmail());
            log.info("OAUTH2_ENREGISTREMENT: New user registered via OAuth2: {}", email);
            return savedUser.getId();
        }
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

package com.example.auth_service.service;

import com.example.auth_service.config.RabbitMQConfig;
import com.example.auth_service.dto.LoginRequest;
import com.example.auth_service.dto.LoginResponse;
import com.example.auth_service.dto.RegisterRequest;
import com.example.auth_service.event.UserRegisteredEvent;
import com.example.auth_service.model.User;
import com.example.auth_service.repository.UserRepository;
import com.example.auth_service.utils.JwtTokenProvider;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RabbitTemplate rabbitTemplate;
    private final JwtTokenProvider jwtTokenProvider;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, RabbitTemplate rabbitTemplate, JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.rabbitTemplate = rabbitTemplate;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    public User registerUser(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("Email already exists");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        User savedUser = userRepository.save(user);

        publishUserRegisteredEvent(savedUser.getId(), savedUser.getEmail());

        return savedUser;
    }

    public LoginResponse login(LoginRequest request) {
        Optional<User> userOptional = userRepository.findByEmail(request.getEmail());
        if (userOptional.isPresent() && passwordEncoder.matches(request.getPassword(), userOptional.get().getPassword())) {
            User user = userOptional.get();
            String accessToken = jwtTokenProvider.generateAccessToken(user.getId().toString());
            String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId().toString());

            // Hacher et sauvegarder le refresh token
            user.setHashedRefreshToken(passwordEncoder.encode(refreshToken)); // Utilisez passwordEncoder pour hacher
            userRepository.save(user);

            return new LoginResponse(accessToken, refreshToken);
        }
        return null;
    }

    // Méthode pour rafraîchir les tokens avec rotation
    public LoginResponse refreshToken(String oldRefreshToken) {
        // 1. Valider l'ancien refresh token
        if (!jwtTokenProvider.validateToken(oldRefreshToken)) {
            log.warn("Invalid or expired refresh token provided.");
            return null;
        }

        String userId = jwtTokenProvider.getUserIdFromToken(oldRefreshToken);
        Optional<User> userOptional = userRepository.findById(UUID.fromString(userId));

        if (userOptional.isPresent()) {
            User user = userOptional.get();

            // 2. Vérifier que le hachage de l'ancien refresh token correspond à celui stocké
            if (user.getHashedRefreshToken() != null && passwordEncoder.matches(oldRefreshToken, user.getHashedRefreshToken())) {
                // 3. Invalider l'ancien refresh token (en supprimant son hachage)
                user.setHashedRefreshToken(null); // Ou marquez-le comme invalide si vous voulez un historique
                userRepository.save(user);

                // 4. Générer un nouveau couple de tokens
                String newAccessToken = jwtTokenProvider.generateAccessToken(userId);
                String newRefreshToken = jwtTokenProvider.generateRefreshToken(userId);

                // 5. Sauvegarder le hachage du nouveau refresh token
                user.setHashedRefreshToken(passwordEncoder.encode(newRefreshToken));
                userRepository.save(user);

                return new LoginResponse(newAccessToken, newRefreshToken);
            } else {
                log.warn("Refresh token provided does not match stored token for user: {}", userId);
                // Si le refresh token ne correspond pas, c'est peut-être une tentative d'abus.
                // Vous pourriez vouloir révoquer tous les tokens de cet utilisateur ici pour plus de sécurité.
                return null;
            }
        }
        log.warn("User not found for refresh token with userId: {}", userId);
        return null;
    }

    // Méthode pour révoquer un refresh token (déconnexion)
    public void revokeRefreshToken(UUID userId) {
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            user.setHashedRefreshToken(null); // Invalide le refresh token
            userRepository.save(user);
            log.info("Refresh token revoked for user: {}", userId);
        }
    }

    // Méthode findOrCreateUser pour OAuth2, mise à jour pour gérer le refresh token
    public UUID findOrCreateUser(String email, String name) {
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            return userOptional.get().getId();
        } else {
            User newUser = new User();
            newUser.setEmail(email);
            newUser.setPassword(passwordEncoder.encode(UUID.randomUUID().toString())); // Générer un mot de passe aléatoire
            User savedUser = userRepository.save(newUser);

            publishUserRegisteredEvent(savedUser.getId(), savedUser.getEmail());

            return savedUser.getId();
        }
    }

    // Méthode saveRefreshToken pour OAuth2, mise à jour pour hacher
    public void saveRefreshToken(UUID userId, String refreshToken) {
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            user.setHashedRefreshToken(passwordEncoder.encode(refreshToken)); // Hacher avant de sauvegarder
            userRepository.save(user);
            log.info("Refresh token saved for user: {}", userId);
        }
    }

    private void publishUserRegisteredEvent(UUID userId, String email) {
        UserRegisteredEvent event = new UserRegisteredEvent();
        event.setUserId(userId);
        event.setEmail(email);

        log.info("Attempting to send UserRegisteredEvent for userId: {} to queue: {}", userId, RabbitMQConfig.QUEUE_NAME);
        try {
            rabbitTemplate.convertAndSend(RabbitMQConfig.QUEUE_NAME, event);
            log.info("Successfully sent UserRegisteredEvent for userId: {}", userId);
        } catch (Exception e) {
            log.error("Failed to send UserRegisteredEvent for userId: {}", userId, e);
        }
    }
}

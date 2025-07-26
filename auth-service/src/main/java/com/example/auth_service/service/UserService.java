package com.example.auth_service.service;

import com.example.auth_service.config.RabbitMQConfig;
import com.example.auth_service.dto.LoginRequest;
import com.example.auth_service.dto.RegisterRequest;
import com.example.auth_service.event.UserRegisteredEvent;
import com.example.auth_service.model.User;
import com.example.auth_service.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.slf4j.Logger; // Importez la classe Logger
import org.slf4j.LoggerFactory; // Importez la classe LoggerFactory

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class); // Déclarez un logger

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RabbitTemplate rabbitTemplate;

    @Value("${jwt.secret}")
    private String secret;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, RabbitTemplate rabbitTemplate) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.rabbitTemplate = rabbitTemplate;
    }

    public User registerUser(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("Email already exists");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        User savedUser = userRepository.save(user);

        // Envoi de l'événement à RabbitMQ
        UserRegisteredEvent event = new UserRegisteredEvent();
        event.setUserId(savedUser.getId());
        event.setEmail(savedUser.getEmail());

        log.info("Attempting to send UserRegisteredEvent for userId: {} to queue: {}", savedUser.getId(), RabbitMQConfig.QUEUE_NAME);
        try {
            rabbitTemplate.convertAndSend(RabbitMQConfig.QUEUE_NAME, event);
            log.info("Successfully sent UserRegisteredEvent for userId: {}", savedUser.getId());
        } catch (Exception e) {
            log.error("Failed to send UserRegisteredEvent for userId: {}", savedUser.getId(), e);
        }

        return savedUser;
    }

    public String login(LoginRequest request) {
        Optional<User> userOptional = userRepository.findByEmail(request.getEmail());
        if (userOptional.isPresent() && passwordEncoder.matches(request.getPassword(), userOptional.get().getPassword())) {
            return generateToken(userOptional.get().getId());
        }
        return null; // Login failed
    }

    public String validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token);

            // Si le token est valide, on récupère l'ID de l'utilisateur
            return Jwts.parserBuilder()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage()); // Loguer l'échec de validation
            return null; // Token invalide
        }
    }

    private String generateToken(UUID userId) {
        return Jwts.builder()
                .setSubject(userId.toString())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30)) // Expire après 30 minutes
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private SecretKey getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}

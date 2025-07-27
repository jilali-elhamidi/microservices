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
            user.setRefreshToken(refreshToken);
            userRepository.save(user);
            return new LoginResponse(accessToken, refreshToken);
        }
        return null;
    }

    public UUID findOrCreateUser(String email, String name) {
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            return userOptional.get().getId();
        } else {
            User newUser = new User();
            newUser.setEmail(email);
            newUser.setPassword(passwordEncoder.encode(""));

            User savedUser = userRepository.save(newUser);

            publishUserRegisteredEvent(savedUser.getId(), savedUser.getEmail());

            return savedUser.getId();
        }
    }

    public String refreshToken(String refreshToken) {
        if (jwtTokenProvider.validateToken(refreshToken)) {
            String userId = jwtTokenProvider.getUserIdFromToken(refreshToken);

            Optional<User> userOptional = userRepository.findById(UUID.fromString(userId));
            if (userOptional.isPresent() && userOptional.get().getRefreshToken().equals(refreshToken)) {
                return jwtTokenProvider.generateAccessToken(userId);
            }
        }
        return null;
    }

    public void saveRefreshToken(UUID userId, String refreshToken) {
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            user.setRefreshToken(refreshToken);
            userRepository.save(user);
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
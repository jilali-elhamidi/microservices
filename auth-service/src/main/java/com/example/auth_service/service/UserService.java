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

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RabbitTemplate rabbitTemplate;
    private final JwtTokenProvider jwtTokenProvider;
    private final TwoFactorAuthService twoFactorAuthService;
    private final AccountLockoutService accountLockoutService;
    private final RefreshTokenManagementService refreshTokenManagementService;
    private final UserRegistrationService userRegistrationService;
    private final OAuth2UserManagementService oauth2UserManagementService;

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_TIME_DURATION_MINUTES = 15;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       RabbitTemplate rabbitTemplate, JwtTokenProvider jwtTokenProvider, TwoFactorAuthService twoFactorAuthService,
                       AccountLockoutService accountLockoutService, RefreshTokenManagementService refreshTokenManagementService,
                       UserRegistrationService userRegistrationService, OAuth2UserManagementService oauth2UserManagementService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.rabbitTemplate = rabbitTemplate;
        this.jwtTokenProvider = jwtTokenProvider;
        this.twoFactorAuthService = twoFactorAuthService;
        this.accountLockoutService = accountLockoutService;
        this.refreshTokenManagementService = refreshTokenManagementService;
        this.userRegistrationService = userRegistrationService;
        this.oauth2UserManagementService = oauth2UserManagementService;
    }

    public User registerUser(RegisterRequest request) {
        return userRegistrationService.registerNewUser(request);
    }

    public LoginResponse login(LoginRequest request, String clientIpAddress) {
        Optional<User> userOptional = userRepository.findByEmail(request.getEmail());

        if (userOptional.isEmpty()) {
            log.warn("AUTHENTIFICATION_ECHEC: User not found for email: {} from IP: {}", request.getEmail(), clientIpAddress);
            return null;
        }

        User user = userOptional.get();

        if (accountLockoutService.checkAndHandleAccountLock(user)) {
            log.warn("AUTHENTIFICATION_ECHEC: Account locked for user: {} from IP: {}", request.getEmail(), clientIpAddress);
            throw new RuntimeException("Account is locked. Please try again later.");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            accountLockoutService.recordFailedLoginAttempt(user, clientIpAddress);
            log.warn("AUTHENTIFICATION_ECHEC: Invalid credentials for user: {} from IP: {}", request.getEmail(), clientIpAddress);
            return null;
        }

        accountLockoutService.resetFailedLoginAttempts(user);
        log.info("AUTHENTIFICATION_SUCCES: User logged in successfully: {} from IP: {}", request.getEmail(), clientIpAddress);

        if (user.is2faEnabled()) {
            return new LoginResponse(null, null, true);
        } else {
            String accessToken = jwtTokenProvider.generateAccessToken(user.getId().toString());
            String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId().toString());
            refreshTokenManagementService.saveRefreshToken(user, refreshToken);
            return new LoginResponse(accessToken, refreshToken, false);
        }
    }

    public LoginResponse verify2FaAndLogin(String email, String twoFaCode, String clientIpAddress) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if (twoFactorAuthService.verifyTotpCode(user, twoFaCode)) {
                String accessToken = jwtTokenProvider.generateAccessToken(user.getId().toString());
                String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId().toString());
                refreshTokenManagementService.saveRefreshToken(user, refreshToken);
                log.info("AUTHENTIFICATION_SUCCES_2FA: User logged in with 2FA successfully: {} from IP: {}", email, clientIpAddress);
                return new LoginResponse(accessToken, refreshToken, false);
            } else {
                log.warn("AUTHENTIFICATION_ECHEC_2FA: Invalid 2FA code for user: {} from IP: {}", email, clientIpAddress);
                return null;
            }
        }
        log.warn("AUTHENTIFICATION_ECHEC_2FA: User not found for 2FA verification: {} from IP: {}", email, clientIpAddress);
        return null;
    }

    public String generate2FaSecret(UUID userId) {
        return twoFactorAuthService.generate2FaSecret(userId);
    }

    public boolean enable2Fa(UUID userId, String twoFaCode) {
        return twoFactorAuthService.enable2Fa(userId, twoFaCode);
    }

    public boolean disable2Fa(UUID userId) {
        return twoFactorAuthService.disable2Fa(userId);
    }

    public LoginResponse refreshToken(String oldRefreshToken, String clientIpAddress) {
        if (!jwtTokenProvider.validateToken(oldRefreshToken)) {
            log.warn("REFRESH_TOKEN_ECHEC: Invalid or expired refresh token provided from IP: {}", clientIpAddress);
            return null;
        }

        String userId = jwtTokenProvider.getUserIdFromToken(oldRefreshToken);
        Optional<User> userOptional = userRepository.findById(UUID.fromString(userId));

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            String newRefreshToken = refreshTokenManagementService.rotateRefreshToken(user, oldRefreshToken, clientIpAddress);
            if (newRefreshToken != null) {
                String newAccessToken = jwtTokenProvider.generateAccessToken(userId);
                return new LoginResponse(newAccessToken, newRefreshToken, false);
            }
        }
        log.warn("REFRESH_TOKEN_ECHEC: User not found for refresh token with userId: {} from IP: {}", userId, clientIpAddress);
        return null;
    }

    public void revokeRefreshToken(UUID userId) {
        refreshTokenManagementService.revokeRefreshToken(userId);
    }

    public UUID findOrCreateUser(String email, String name) {
        return oauth2UserManagementService.findOrCreateOAuth2User(email, name);
    }

    // Nouvelle méthode pour générer et sauvegarder les tokens après une connexion OAuth2
    public LoginResponse generateAndSaveTokensForOAuth2User(UUID userId) {
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            String accessToken = jwtTokenProvider.generateAccessToken(user.getId().toString());
            String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId().toString());
            refreshTokenManagementService.saveRefreshToken(user, refreshToken);
            return new LoginResponse(accessToken, refreshToken, false);
        }
        log.warn("OAUTH2_TOKEN_GEN_ECHEC: User not found to generate tokens for userId: {}", userId);
        return null;
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

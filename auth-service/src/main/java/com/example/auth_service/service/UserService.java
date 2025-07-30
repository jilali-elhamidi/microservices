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
    private final GoogleAuthenticator gAuth;

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_TIME_DURATION_MINUTES = 15;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, RabbitTemplate rabbitTemplate, JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.rabbitTemplate = rabbitTemplate;
        this.jwtTokenProvider = jwtTokenProvider;

        GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder gaConfigBuilder =
                new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder();
        gaConfigBuilder.setTimeStepSizeInMillis(TimeUnit.SECONDS.toMillis(30));
        gaConfigBuilder.setWindowSize(5);

        this.gAuth = new GoogleAuthenticator(gaConfigBuilder.build());
    }

    public User registerUser(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("Email already exists");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.set2faEnabled(false);
        user.setFailedLoginAttempts(0);
        user.setAccountLocked(false);
        userRepository.save(user);

        publishUserRegisteredEvent(user.getId(), user.getEmail());
        log.info("UTILISATEUR_ENREGISTRE: User registered successfully: {}", user.getEmail());
        return user;
    }

    public LoginResponse login(LoginRequest request, String clientIpAddress) {
        Optional<User> userOptional = userRepository.findByEmail(request.getEmail());

        if (userOptional.isEmpty()) {
            log.warn("AUTHENTIFICATION_ECHEC: User not found for email: {} from IP: {}", request.getEmail(), clientIpAddress);
            return null;
        }

        User user = userOptional.get();

        if (user.isAccountLocked()) {
            if (user.getLockTime() != null && LocalDateTime.now().isBefore(user.getLockTime().plusMinutes(LOCK_TIME_DURATION_MINUTES))) {
                log.warn("AUTHENTIFICATION_ECHEC: Account locked for user: {} from IP: {}", request.getEmail(), clientIpAddress);
                throw new RuntimeException("Account is locked. Please try again later.");
            } else {
                user.setAccountLocked(false);
                user.setFailedLoginAttempts(0);
                user.setLockTime(null);
                userRepository.save(user);
                log.info("COMPTE_DEVERROUILLE: Account unlocked for user: {}", user.getEmail());
            }
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
            if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
                user.setAccountLocked(true);
                user.setLockTime(LocalDateTime.now());
                log.warn("COMPTE_VERROUILLE: Account locked for user: {} after {} failed attempts from IP: {}", request.getEmail(), user.getFailedLoginAttempts(), clientIpAddress);
            }
            userRepository.save(user);
            log.warn("AUTHENTIFICATION_ECHEC: Invalid credentials for user: {} from IP: {}", request.getEmail(), clientIpAddress);
            return null;
        }

        user.setFailedLoginAttempts(0);
        user.setAccountLocked(false);
        user.setLockTime(null);
        userRepository.save(user);

        log.info("AUTHENTIFICATION_SUCCES: User logged in successfully: {} from IP: {}", request.getEmail(), clientIpAddress);

        if (user.is2faEnabled()) {
            return new LoginResponse(null, null, true);
        } else {
            String accessToken = jwtTokenProvider.generateAccessToken(user.getId().toString());
            String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId().toString());
            user.setHashedRefreshToken(passwordEncoder.encode(refreshToken));
            userRepository.save(user);
            return new LoginResponse(accessToken, refreshToken, false);
        }
    }

    public LoginResponse verify2FaAndLogin(String email, String twoFaCode, String clientIpAddress) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if (user.is2faEnabled() && user.getTwoFaSecret() != null) {
                if (gAuth.authorize(user.getTwoFaSecret(), Integer.parseInt(twoFaCode))) {
                    String accessToken = jwtTokenProvider.generateAccessToken(user.getId().toString());
                    String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId().toString());
                    user.setHashedRefreshToken(passwordEncoder.encode(refreshToken));
                    userRepository.save(user);
                    return new LoginResponse(accessToken, refreshToken, false);
                } else {
                    log.warn("AUTHENTIFICATION_ECHEC_2FA: Invalid 2FA code for user: {} from IP: {}", email, clientIpAddress);
                    return null;
                }
            } else {
                log.warn("AUTHENTIFICATION_ECHEC_2FA: 2FA not enabled or secret missing for user: {} from IP: {}", email, clientIpAddress);
                return null;
            }
        }
        log.warn("AUTHENTIFICATION_ECHEC_2FA: User not found for 2FA verification: {} from IP: {}", email, clientIpAddress);
        return null;
    }

    public String generate2FaSecret(UUID userId) {
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if (user.is2faEnabled()) {
                throw new RuntimeException("2FA is already enabled for this user.");
            }
            // Correction: Utiliser createCredentials()
            GoogleAuthenticatorKey key = gAuth.createCredentials();
            user.setTwoFaSecret(key.getKey());
            userRepository.save(user);

            // Correction: Utiliser getOtpAuthURL() qui prend GoogleAuthenticatorKey
            String qrCodeUrl = GoogleAuthenticatorQRGenerator.getOtpAuthURL("VotreApp", user.getEmail(), key);
            log.info("2FA_SECRET_GENERE: Secret generated for user: {}", user.getEmail());
            return qrCodeUrl;
        }
        log.warn("2FA_SECRET_ECHEC: User not found to generate 2FA secret for userId: {}", userId);
        return null;
    }

    public boolean enable2Fa(UUID userId, String twoFaCode) {
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if (user.is2faEnabled()) {
                log.warn("2FA_ACTIVATION_ECHEC: 2FA already enabled for user: {}", userId);
                return false;
            }
            if (user.getTwoFaSecret() == null) {
                log.warn("2FA_ACTIVATION_ECHEC: 2FA secret not generated for user: {}", userId);
                return false;
            }

            if (gAuth.authorize(user.getTwoFaSecret(), Integer.parseInt(twoFaCode))) {
                user.set2faEnabled(true);
                userRepository.save(user);
                log.info("2FA_ACTIVE: 2FA enabled successfully for user: {}", user.getEmail());
                return true;
            } else {
                log.warn("2FA_ACTIVATION_ECHEC: Invalid 2FA code provided during 2FA activation for user: {}", userId);
                return false;
            }
        }
        log.warn("2FA_ACTIVATION_ECHEC: User not found for 2FA activation: {}", userId);
        return false;
    }

    public boolean disable2Fa(UUID userId) {
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            user.set2faEnabled(false);
            user.setTwoFaSecret(null);
            userRepository.save(user);
            log.info("2FA_DESACTIVE: 2FA disabled successfully for user: {}", user.getEmail());
            return true;
        }
        log.warn("2FA_DESACTIVATION_ECHEC: User not found for 2FA deactivation: {}", userId);
        return false;
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

            if (user.getHashedRefreshToken() != null && passwordEncoder.matches(oldRefreshToken, user.getHashedRefreshToken())) {
                user.setHashedRefreshToken(null);
                userRepository.save(user);
                log.info("REFRESH_TOKEN_ROTATION: Old refresh token invalidated for user: {} from IP: {}", user.getEmail(), clientIpAddress);

                String newAccessToken = jwtTokenProvider.generateAccessToken(userId);
                String newRefreshToken = jwtTokenProvider.generateRefreshToken(userId);

                return new LoginResponse(newAccessToken, newRefreshToken, false);
            } else {
                log.warn("REFRESH_TOKEN_COMPROMIS: Refresh token provided does not match stored token or already used for user: {} from IP: {}", user.getEmail(), clientIpAddress);
                user.setHashedRefreshToken(null);
                userRepository.save(user);
                log.error("REFRESH_TOKEN_REVOCATION_FORCEE: All refresh tokens revoked for user: {} due to suspected compromise from IP: {}", user.getEmail(), clientIpAddress);
                return null;
            }
        }
        log.warn("REFRESH_TOKEN_ECHEC: User not found for refresh token with userId: {} from IP: {}", userId, clientIpAddress);
        return null;
    }

    public void revokeRefreshToken(UUID userId) {
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            user.setHashedRefreshToken(null);
            userRepository.save(user);
            log.info("DECONNEXION_SUCCES: Refresh token revoked for user: {}", user.getEmail());
        } else {
            log.warn("DECONNEXION_ECHEC: User not found to revoke refresh token for userId: {}", userId);
        }
    }

    public UUID findOrCreateUser(String email, String name) {
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            log.info("OAUTH2_CONNEXION: Existing user logged in via OAuth2: {}", email);
            return userOptional.get().getId();
        } else {
            User newUser = new User();
            newUser.setEmail(email);
            newUser.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
            newUser.set2faEnabled(false);
            newUser.setFailedLoginAttempts(0);
            newUser.setAccountLocked(false);
            User savedUser = userRepository.save(newUser);

            publishUserRegisteredEvent(savedUser.getId(), savedUser.getEmail());
            log.info("OAUTH2_ENREGISTREMENT: New user registered via OAuth2: {}", email);
            return savedUser.getId();
        }
    }

    public void saveRefreshToken(UUID userId, String refreshToken) {
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            user.setHashedRefreshToken(passwordEncoder.encode(refreshToken));
            userRepository.save(user);
            log.info("OAUTH2_REFRESH_TOKEN_SAUVEGARDE: Refresh token saved for OAuth2 user: {}", user.getEmail());
        } else {
            log.warn("OAUTH2_REFRESH_TOKEN_ECHEC: User not found to save refresh token for userId: {}", userId);
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

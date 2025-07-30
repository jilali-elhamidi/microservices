package com.example.auth_service.service;

import com.example.auth_service.model.User;
import com.example.auth_service.repository.UserRepository;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
public class TwoFactorAuthService {

    private static final Logger log = LoggerFactory.getLogger(TwoFactorAuthService.class);

    private final UserRepository userRepository;
    private final GoogleAuthenticator gAuth;

    public TwoFactorAuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
        // Configuration de GoogleAuthenticator
        GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder gaConfigBuilder =
                new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder();
        gaConfigBuilder.setTimeStepSizeInMillis(TimeUnit.SECONDS.toMillis(30));
        gaConfigBuilder.setWindowSize(5); // Permet de valider des codes légèrement en avance ou en retard

        this.gAuth = new GoogleAuthenticator(gaConfigBuilder.build());
    }


    public String generate2FaSecret(UUID userId) {
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if (user.is2faEnabled()) {
                throw new RuntimeException("2FA is already enabled for this user.");
            }
            GoogleAuthenticatorKey key = gAuth.createCredentials();
            user.setTwoFaSecret(key.getKey());
            userRepository.save(user);

            // Pour l'affichage, générer l'URL du QR code
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
            user.setTwoFaSecret(null); // Supprimer le secret pour désactiver complètement
            userRepository.save(user);
            log.info("2FA_DESACTIVE: 2FA disabled successfully for user: {}", user.getEmail());
            return true;
        }
        log.warn("2FA_DESACTIVATION_ECHEC: User not found for 2FA deactivation: {}", userId);
        return false;
    }


    public boolean verifyTotpCode(User user, String twoFaCode) {
        if (user.is2faEnabled() && user.getTwoFaSecret() != null) {
            return gAuth.authorize(user.getTwoFaSecret(), Integer.parseInt(twoFaCode));
        }
        return false;
    }
}

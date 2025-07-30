package com.example.auth_service.service;

import com.example.auth_service.model.User;
import com.example.auth_service.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class AccountLockoutService {

    private static final Logger log = LoggerFactory.getLogger(AccountLockoutService.class);

    private final UserRepository userRepository;

    // Configuration pour la limitation des tentatives de connexion
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_TIME_DURATION_MINUTES = 15;

    public AccountLockoutService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    public boolean recordFailedLoginAttempt(User user, String clientIpAddress) {
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
            user.setAccountLocked(true);
            user.setLockTime(LocalDateTime.now());
            log.warn("COMPTE_VERROUILLE: Account locked for user: {} after {} failed attempts from IP: {}", user.getEmail(), user.getFailedLoginAttempts(), clientIpAddress);
            userRepository.save(user);
            return true;
        }
        userRepository.save(user); // Sauvegarder le compteur mis à jour
        return false;
    }


    public boolean checkAndHandleAccountLock(User user) {
        if (user.isAccountLocked()) {
            if (user.getLockTime() != null && LocalDateTime.now().isBefore(user.getLockTime().plusMinutes(LOCK_TIME_DURATION_MINUTES))) {
                return true; // Compte toujours verrouillé
            } else {
                // Le temps de verrouillage est écoulé, déverrouiller le compte
                user.setAccountLocked(false);
                user.setFailedLoginAttempts(0);
                user.setLockTime(null);
                userRepository.save(user);
                log.info("COMPTE_DEVERROUILLE: Account unlocked for user: {}", user.getEmail());
                return false; // Compte déverrouillé
            }
        }
        return false; // Compte non verrouillé
    }


    public void resetFailedLoginAttempts(User user) {
        user.setFailedLoginAttempts(0);
        user.setAccountLocked(false);
        user.setLockTime(null);
        userRepository.save(user);
    }
}

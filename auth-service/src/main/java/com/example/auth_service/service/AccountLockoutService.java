package com.example.auth_service.service;

import com.example.auth_service.model.User;
import com.example.auth_service.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest; // Ajouté pour obtenir l'IP
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate; // Import RedisTemplate
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

@Service
public class AccountLockoutService {

    private static final Logger log = LoggerFactory.getLogger(AccountLockoutService.class);

    private final UserRepository userRepository;
    private final RedisTemplate<String, Object> redisTemplate; // Injection de RedisTemplate

    // Configuration pour la limitation des tentatives de connexion
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_TIME_DURATION_MINUTES = 15; // Durée du verrouillage en minutes
    private static final String FAILED_LOGIN_PREFIX = "failed_login:"; // Préfixe pour les clés Redis
    private static final String IP_LOCK_PREFIX = "ip_lock:"; // Préfixe pour le verrouillage IP

    public AccountLockoutService(UserRepository userRepository, RedisTemplate<String, Object> redisTemplate) {
        this.userRepository = userRepository;
        this.redisTemplate = redisTemplate;
    }

    public void recordFailedLoginAttempt(User user, String clientIpAddress) {
        // Incrémenter le compteur pour l'utilisateur
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
        userRepository.save(user);

        // Incrémenter le compteur pour l'IP dans Redis
        String ipKey = IP_LOCK_PREFIX + clientIpAddress;
        Long ipFailedAttempts = redisTemplate.opsForValue().increment(ipKey, 1);
        redisTemplate.expire(ipKey, LOCK_TIME_DURATION_MINUTES, TimeUnit.MINUTES); // Expire après le temps de verrouillage

        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
            user.setAccountLocked(true);
            user.setLockTime(LocalDateTime.now());
            userRepository.save(user);
            log.warn("COMPTE_VERROUILLE: Account locked for user: {} after {} failed attempts from IP: {}", user.getEmail(), user.getFailedLoginAttempts(), clientIpAddress);
        }

        // Si l'IP dépasse le seuil (peut être différent du seuil utilisateur)
        // Vous pouvez définir un seuil IP ici aussi, par exemple 10 tentatives en 15 minutes
        if (ipFailedAttempts != null && ipFailedAttempts > (MAX_FAILED_ATTEMPTS * 2)) { // Exemple: 2x le seuil utilisateur
            // Bloquer temporairement l'IP dans Redis
            log.warn("IP_VERROUILLEE: IP {} locked for {} minutes due to excessive failed login attempts.", clientIpAddress, LOCK_TIME_DURATION_MINUTES);
            // Pas besoin de faire plus ici, la vérification sera faite par le contrôleur ou un filtre
        }
    }

    public boolean checkAndHandleAccountLock(User user) {
        if (user.isAccountLocked()) {
            if (user.getLockTime() != null && LocalDateTime.now().isBefore(user.getLockTime().plusMinutes(LOCK_TIME_DURATION_MINUTES))) {
                return true; // Compte toujours verrouillé
            } else {
                // Le temps de verrouillage est écoulé, déverrouiller le compte
                resetFailedLoginAttempts(user); // Réinitialise aussi le verrouillage
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
        // Supprimer le compteur d'IP de Redis si l'utilisateur se connecte depuis cette IP
        // redisTemplate.delete(IP_LOCK_PREFIX + clientIpAddress); // Nécessiterait de passer l'IP ici
    }

    public String getClientIpAddress(HttpServletRequest request) {
        String xForwardedForHeader = request.getHeader("X-Forwarded-For");
        if (xForwardedForHeader != null && !xForwardedForHeader.isEmpty()) {
            // Prend la première IP dans la liste (la plus à gauche)
            return xForwardedForHeader.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}

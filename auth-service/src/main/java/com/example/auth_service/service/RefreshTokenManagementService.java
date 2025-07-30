package com.example.auth_service.service;

import com.example.auth_service.model.User;
import com.example.auth_service.repository.UserRepository;
import com.example.auth_service.utils.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenManagementService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenManagementService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public RefreshTokenManagementService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }


    public void saveRefreshToken(User user, String refreshToken) {
        user.setHashedRefreshToken(passwordEncoder.encode(refreshToken));
        userRepository.save(user);
        log.info("REFRESH_TOKEN_SAUVEGARDE: Refresh token saved for user: {}", user.getEmail());
    }


    public String rotateRefreshToken(User user, String oldRefreshToken, String clientIpAddress) {
        // Vérifier que le hachage de l'ancien refresh token correspond à celui stocké
        if (user.getHashedRefreshToken() != null && passwordEncoder.matches(oldRefreshToken, user.getHashedRefreshToken())) {
            // Invalider l'ancien refresh token (rotation)
            user.setHashedRefreshToken(null); // Marquer comme null pour l'invalider
            userRepository.save(user);
            log.info("REFRESH_TOKEN_ROTATION: Old refresh token invalidated for user: {} from IP: {}", user.getEmail(), clientIpAddress);

            String newRefreshToken = jwtTokenProvider.generateRefreshToken(user.getId().toString());

            // Sauvegarder le hachage du nouveau refresh token
            user.setHashedRefreshToken(passwordEncoder.encode(newRefreshToken));
            userRepository.save(user);
            log.info("REFRESH_TOKEN_SUCCES: New refresh token generated and stored for user: {} from IP: {}", user.getEmail(), clientIpAddress);

            return newRefreshToken;
        } else {
            log.warn("REFRESH_TOKEN_COMPROMIS: Refresh token provided does not match stored token or already used for user: {} from IP: {}", user.getEmail(), clientIpAddress);
            // Si le refresh token ne correspond pas, c'est peut-être une tentative d'abus.
            // Révoquer tous les tokens de cet utilisateur pour plus de sécurité.
            user.setHashedRefreshToken(null);
            userRepository.save(user);
            log.error("REFRESH_TOKEN_REVOCATION_FORCEE: All refresh tokens revoked for user: {} due to suspected compromise from IP: {}", user.getEmail(), clientIpAddress);
            return null;
        }
    }


    public void revokeRefreshToken(UUID userId) {
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            user.setHashedRefreshToken(null); // Invalide le refresh token
            userRepository.save(user);
            log.info("DECONNEXION_SUCCES: Refresh token revoked for user: {}", user.getEmail());
        } else {
            log.warn("DECONNEXION_ECHEC: User not found to revoke refresh token for userId: {}", userId);
        }
    }
}

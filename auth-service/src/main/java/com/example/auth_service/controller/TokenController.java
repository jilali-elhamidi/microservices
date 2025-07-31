package com.example.auth_service.controller;

import com.example.auth_service.dto.LoginResponse;
import com.example.auth_service.service.UserService;
import com.example.auth_service.utils.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated; // Peut être nécessaire si des DTOs sont validés ici
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/auth") // Garde le même chemin de base /auth
@Validated // Active la validation pour ce contrôleur
public class TokenController {

    private static final Logger log = LoggerFactory.getLogger(TokenController.class);

    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;

    public TokenController(UserService userService, JwtTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<LoginResponse> refreshToken(@RequestBody String refreshToken, HttpServletRequest httpRequest) {
        String clientIpAddress = httpRequest.getRemoteAddr();
        LoginResponse newTokens = userService.refreshToken(refreshToken, clientIpAddress);
        if (newTokens != null) {
            log.info("API_REFRESH_TOKEN_SUCCES: Token refreshed for user from IP: {}", clientIpAddress);
            return ResponseEntity.ok(newTokens);
        }
        log.warn("API_REFRESH_TOKEN_ECHEC: Refresh token failed from IP: {}", clientIpAddress);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
    }

    @GetMapping("/validateToken")
    public ResponseEntity<String> validateToken(@RequestHeader("Authorization") String token) {
        if (token != null && token.startsWith("Bearer ")) {
            String jwt = token.substring(7);
            if (jwtTokenProvider.validateToken(jwt)) {
                String userId = jwtTokenProvider.getUserIdFromToken(jwt);
                log.info("API_VALIDATE_TOKEN_SUCCES: Token validated for user ID: {}", userId);
                return ResponseEntity.ok(userId);
            }
        }
        log.warn("API_VALIDATE_TOKEN_ECHEC: Invalid or missing token.");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Token");
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String token) {
        if (token != null && token.startsWith("Bearer ")) {
            String accessToken = token.substring(7);
            try {
                String userId = jwtTokenProvider.getUserIdFromToken(accessToken);
                userService.revokeRefreshToken(UUID.fromString(userId));
                log.info("API_LOGOUT_SUCCES: User logged out successfully: {}", userId);
                return ResponseEntity.ok("Logged out successfully");
            } catch (Exception e) {
                log.error("API_LOGOUT_ECHEC: Failed to logout for user ID: {}. Reason: {}", jwtTokenProvider.getUserIdFromToken(accessToken), e.getMessage(), e);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Failed to logout: " + e.getMessage());
            }
        }
        log.warn("API_LOGOUT_ECHEC: Bearer token required for logout.");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Bearer token required for logout");
    }
}
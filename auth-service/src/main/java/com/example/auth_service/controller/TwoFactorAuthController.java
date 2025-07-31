
package com.example.auth_service.controller;

import com.example.auth_service.dto.LoginRequest;
import com.example.auth_service.dto.LoginResponse;
import com.example.auth_service.service.UserService;
import com.example.auth_service.utils.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/auth/2fa") // Nouveau chemin de base pour les endpoints 2FA
@Validated // Active la validation pour ce contrôleur
public class TwoFactorAuthController {

    private static final Logger log = LoggerFactory.getLogger(TwoFactorAuthController.class);

    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;

    public TwoFactorAuthController(UserService userService, JwtTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/verify")
    public ResponseEntity<LoginResponse> verify2Fa(@Valid @RequestBody LoginRequest request, @RequestParam String code, HttpServletRequest httpRequest) {
        String clientIpAddress = httpRequest.getRemoteAddr();
        LoginResponse response = userService.verify2FaAndLogin(request.getEmail(), code, clientIpAddress);
        if (response != null) {
            log.info("API_2FA_VERIFY_SUCCES: 2FA verification successful for email: {} from IP: {}", request.getEmail(), clientIpAddress);
            return ResponseEntity.ok(response);
        }
        log.warn("API_2FA_VERIFY_ECHEC: 2FA verification failed for email: {} from IP: {}. Invalid code.", request.getEmail(), clientIpAddress);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
    }

    @GetMapping("/generate-secret")
    public ResponseEntity<String> generate2FaSecret(@RequestHeader("Authorization") String token) {
        if (token != null && token.startsWith("Bearer ")) {
            String jwt = token.substring(7);
            if (jwtTokenProvider.validateToken(jwt)) {
                String userId = jwtTokenProvider.getUserIdFromToken(jwt);
                try {
                    String qrCodeUrl = userService.generate2FaSecret(UUID.fromString(userId));
                    log.info("API_2FA_SECRET_GENERE: 2FA secret generated for user ID: {}", userId);
                    return ResponseEntity.ok(qrCodeUrl);
                } catch (RuntimeException e) {
                    log.error("API_2FA_SECRET_ECHEC: Failed to generate 2FA secret for user ID: {}. Reason: {}", userId, e.getMessage());
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
                }
            }
        }
        log.warn("API_2FA_SECRET_ECHEC: Invalid token or not authenticated for 2FA secret generation.");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Token or not authenticated.");
    }

    @PostMapping("/enable")
    public ResponseEntity<?> enable2Fa(@RequestHeader("Authorization") String token, @RequestParam String code) {
        if (token != null && token.startsWith("Bearer ")) {
            String jwt = token.substring(7);
            if (jwtTokenProvider.validateToken(jwt)) {
                String userId = jwtTokenProvider.getUserIdFromToken(jwt);
                if (userService.enable2Fa(UUID.fromString(userId), code)) {
                    log.info("API_2FA_ENABLE_SUCCES: 2FA enabled for user ID: {}", userId);
                    return ResponseEntity.ok("2FA enabled successfully.");
                }
            }
        }
        log.warn("API_2FA_ENABLE_ECHEC: Invalid token or 2FA activation failed.");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Token or 2FA activation failed.");
    }

    @PostMapping("/disable")
    public ResponseEntity<?> disable2Fa(@RequestHeader("Authorization") String token) {
        if (token != null && token.startsWith("Bearer ")) {
            String jwt = token.substring(7);
            if (jwtTokenProvider.validateToken(jwt)) {
                String userId = jwtTokenProvider.getUserIdFromToken(jwt);
                if (userService.disable2Fa(UUID.fromString(userId))) {
                    log.info("API_2FA_DISABLE_SUCCES: 2FA disabled for user ID: {}", userId);
                    return ResponseEntity.ok("2FA disabled successfully.");
                }
            }
        }
        log.warn("API_2FA_DISABLE_ECHEC: Invalid token or 2FA deactivation failed.");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Token or 2FA deactivation failed.");
    }
}

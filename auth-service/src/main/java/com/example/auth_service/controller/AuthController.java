package com.example.auth_service.controller;

import com.example.auth_service.dto.LoginRequest;
import com.example.auth_service.dto.LoginResponse;
import com.example.auth_service.dto.RegisterRequest;
import com.example.auth_service.service.UserService;
import com.example.auth_service.utils.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException; // Import pour la gestion des erreurs de validation
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthController(UserService userService, JwtTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) { // @Valid est crucial ici
        try {
            userService.registerUser(request);
            log.info("API_REGISTER_SUCCES: User registration request successful for email: {}", request.getEmail());
            return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully");
        } catch (RuntimeException e) {
            log.warn("API_REGISTER_ECHEC: User registration request failed for email: {}. Reason: {}", request.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest) { // @Valid est crucial ici
        String clientIpAddress = httpRequest.getRemoteAddr();
        try { // Ajout d'un try-catch pour la logique de verrouillage
            LoginResponse response = userService.login(request, clientIpAddress);
            if (response != null) {
                log.info("API_LOGIN_SUCCES: Login request successful for email: {} from IP: {}", request.getEmail(), clientIpAddress);
                return ResponseEntity.ok(response);
            }
            log.warn("API_LOGIN_ECHEC: Login request failed for email: {} from IP: {}. Invalid credentials.", request.getEmail(), clientIpAddress);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        } catch (RuntimeException e) { // Capture l'exception de compte verrouillé
            log.warn("API_LOGIN_ECHEC: Login request failed for email: {} from IP: {}. Reason: {}", request.getEmail(), clientIpAddress, e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null); // Utilisez FORBIDDEN pour compte verrouillé
        }
    }

    @PostMapping("/2fa/verify")
    public ResponseEntity<LoginResponse> verify2Fa(@Valid @RequestBody LoginRequest request, @RequestParam String code, HttpServletRequest httpRequest) { // @Valid est crucial ici
        String clientIpAddress = httpRequest.getRemoteAddr();
        LoginResponse response = userService.verify2FaAndLogin(request.getEmail(), code, clientIpAddress);
        if (response != null) {
            log.info("API_2FA_VERIFY_SUCCES: 2FA verification successful for email: {} from IP: {}", request.getEmail(), clientIpAddress);
            return ResponseEntity.ok(response);
        }
        log.warn("API_2FA_VERIFY_ECHEC: 2FA verification failed for email: {} from IP: {}. Invalid code.", request.getEmail(), clientIpAddress);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
    }

    @GetMapping("/2fa/generate-secret")
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

    @PostMapping("/2fa/enable")
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

    @PostMapping("/2fa/disable")
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

    // GESTIONNAIRE D'EXCEPTIONS POUR LES ERREURS DE VALIDATION
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Map<String, String> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
                errors.put(error.getField(), error.getDefaultMessage()));
        log.warn("API_VALIDATION_ECHEC: Validation errors: {}", errors);
        return errors;
    }
}

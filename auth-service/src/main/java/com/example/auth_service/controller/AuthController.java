package com.example.auth_service.controller;

import com.example.auth_service.dto.LoginRequest;
import com.example.auth_service.dto.LoginResponse;
import com.example.auth_service.dto.RegisterRequest;
import com.example.auth_service.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@Validated // Active la validation pour ce contrôleur
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final UserService userService;
    // JwtTokenProvider n'est plus directement nécessaire ici, car UserService gère la logique des tokens
    // private final JwtTokenProvider jwtTokenProvider;

    public AuthController(UserService userService) { // Constructeur mis à jour
        this.userService = userService;
        // this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
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
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        String clientIpAddress = httpRequest.getRemoteAddr();
        try {
            LoginResponse response = userService.login(request, clientIpAddress);
            if (response != null) {
                log.info("API_LOGIN_SUCCES: Login request successful for email: {} from IP: {}", request.getEmail(), clientIpAddress);
                return ResponseEntity.ok(response);
            }
            log.warn("API_LOGIN_ECHEC: Login request failed for email: {} from IP: {}. Invalid credentials.", request.getEmail(), clientIpAddress);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        } catch (RuntimeException e) {
            log.warn("API_LOGIN_ECHEC: Login request failed for email: {} from IP: {}. Reason: {}", request.getEmail(), clientIpAddress, e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
        }
    }

    // Le gestionnaire d'exceptions reste ici pour toutes les validations du package /auth
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

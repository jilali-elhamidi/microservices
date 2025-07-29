// src/main/java/com/example/auth_service/controller/AuthController.java
package com.example.auth_service.controller;

import com.example.auth_service.dto.LoginRequest;
import com.example.auth_service.dto.LoginResponse;
import com.example.auth_service.dto.RegisterRequest;
import com.example.auth_service.service.UserService;
import com.example.auth_service.utils.JwtTokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider; // Garder pour validateToken

    public AuthController(UserService userService, JwtTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        try {
            userService.registerUser(request);
            return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully");
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        LoginResponse response = userService.login(request);
        if (response != null) {
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null); // Retourne null dans le corps en cas d'échec
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<LoginResponse> refreshToken(@RequestBody String refreshToken) { // Le client envoie juste le refresh token
        LoginResponse newTokens = userService.refreshToken(refreshToken);
        if (newTokens != null) {
            return ResponseEntity.ok(newTokens);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null); // Retourne null dans le corps en cas d'échec
    }

    @GetMapping("/validateToken")
    public ResponseEntity<String> validateToken(@RequestHeader("Authorization") String token) {
        if (token != null && token.startsWith("Bearer ")) {
            String jwt = token.substring(7);
            if (jwtTokenProvider.validateToken(jwt)) {
                String userId = jwtTokenProvider.getUserIdFromToken(jwt);
                return ResponseEntity.ok(userId);
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Token");
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String token) {
        if (token != null && token.startsWith("Bearer ")) {
            String accessToken = token.substring(7);
            // Dans une architecture JWT stateless, la déconnexion nécessite la révocation du refresh token
            // Ou la mise en place d'une liste noire pour les access tokens si leur durée de vie est longue.
            // Ici, nous allons révoquer le refresh token associé à l'utilisateur de l'access token.
            try {
                String userId = jwtTokenProvider.getUserIdFromToken(accessToken);
                userService.revokeRefreshToken(UUID.fromString(userId));
                return ResponseEntity.ok("Logged out successfully");
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Failed to logout: " + e.getMessage());
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Bearer token required for logout");
    }
}

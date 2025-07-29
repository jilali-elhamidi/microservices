// src/main/java/com/example/auth_service/controller/OAuth2LoginController.java
package com.example.auth_service.controller;

import com.example.auth_service.dto.LoginResponse;
import com.example.auth_service.service.UserService;
import com.example.auth_service.utils.JwtTokenProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
public class OAuth2LoginController {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserService userService;

    public OAuth2LoginController(JwtTokenProvider jwtTokenProvider, UserService userService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.userService = userService;
    }

    @GetMapping("/login-success")
    public ResponseEntity<LoginResponse> oauth2LoginSuccess(@AuthenticationPrincipal OAuth2User oauth2User) {
        if (oauth2User == null) {
            return ResponseEntity.status(401).body(null);
        }

        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");

        UUID userId = userService.findOrCreateUser(email, name);
        String accessToken = jwtTokenProvider.generateAccessToken(userId.toString());
        String refreshToken = jwtTokenProvider.generateRefreshToken(userId.toString());

        // Gérer la sauvegarde du refresh token dans la base de données (haché)
        userService.saveRefreshToken(userId, refreshToken);

        return ResponseEntity.ok(new LoginResponse(accessToken, refreshToken));
    }
}

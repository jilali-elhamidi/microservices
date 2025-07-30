package com.example.auth_service.controller;

import com.example.auth_service.dto.LoginResponse;
import com.example.auth_service.service.UserService;
import com.example.auth_service.utils.JwtTokenProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

@RestController
public class OAuth2LoginController {

    private static final Logger log = LoggerFactory.getLogger(OAuth2LoginController.class);

    private final JwtTokenProvider jwtTokenProvider;
    private final UserService userService;

    public OAuth2LoginController(JwtTokenProvider jwtTokenProvider, UserService userService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.userService = userService;
    }

    @GetMapping("/login-success")
    public ResponseEntity<LoginResponse> oauth2LoginSuccess(@AuthenticationPrincipal OAuth2User oauth2User) {
        if (oauth2User == null) {
            log.warn("OAUTH2_LOGIN_ECHEC: OAuth2User is null during login success.");
            return ResponseEntity.status(401).body(null);
        }

        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");
        String clientIpAddress = "N/A"; // L'adresse IP est plus difficile à obtenir directement ici pour OAuth2

        UUID userId = userService.findOrCreateUser(email, name);
        String accessToken = jwtTokenProvider.generateAccessToken(userId.toString());
        String refreshToken = jwtTokenProvider.generateRefreshToken(userId.toString());

        userService.saveRefreshToken(userId, refreshToken);
        log.info("OAUTH2_LOGIN_SUCCES: User {} logged in successfully via OAuth2. User ID: {}", email, userId);
        return ResponseEntity.ok(new LoginResponse(accessToken, refreshToken, false)); // requires2Fa est false pour OAuth2
    }
}

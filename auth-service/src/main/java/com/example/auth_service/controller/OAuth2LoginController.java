package com.example.auth_service.controller;

import com.example.auth_service.service.UserService;
import com.example.auth_service.utils.JwtTokenProvider;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
// Ne pas importer RedirectView car on ne l'utilise plus
import org.springframework.http.ResponseEntity;
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
    public ResponseEntity<String> oauth2LoginSuccess(@AuthenticationPrincipal OAuth2User oauth2User) {
        if (oauth2User == null) {
            return ResponseEntity.status(401).body("User not authenticated with Google.");
        }

        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");

        UUID userId = userService.findOrCreateUser(email, name);
        String jwtToken = jwtTokenProvider.generateToken(userId.toString());

        // Au lieu de rediriger, on renvoie directement le token dans le corps de la réponse
        return ResponseEntity.ok(jwtToken);
    }
}
package com.example.profile_service.controller;

import com.example.profile_service.dto.ProfileUpdateRequest;
import com.example.profile_service.model.Profile;
import com.example.profile_service.service.ProfileService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.UUID;

@RestController
@RequestMapping("/profiles")
public class ProfileController {

    private final ProfileService profileService;
    private final WebClient authWebClient;

    public ProfileController(ProfileService profileService,
                             @Qualifier("authWebClient") WebClient authWebClient) {
        this.profileService = profileService;
        this.authWebClient = authWebClient;
    }

    private Mono<String> validateToken(String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            return Mono.empty();
        }

        return authWebClient.get()
                .uri("/auth/validateToken")
                .header(HttpHeaders.AUTHORIZATION, token)
                .retrieve()
                .bodyToMono(String.class)
                .onErrorResume(WebClientResponseException.class, e -> {
                    System.err.println("Token validation error: " + e.getMessage());
                    return Mono.empty();
                });
    }

    @GetMapping("/{userId}")
    public Mono<ResponseEntity<?>> getProfile(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token,
            @PathVariable UUID userId) {

        return validateToken(token)
                .flatMap(validatedUserId -> {
                    if (!userId.toString().equals(validatedUserId)) {
                        return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build());
                    }

                    return Mono.justOrEmpty(profileService.getProfileByUserId(userId))
                            .map(ResponseEntity::ok)
                            .defaultIfEmpty(ResponseEntity.notFound().build());
                })
                .switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()));
    }

    @PutMapping("/{userId}")
    public Mono<ResponseEntity<?>> updateProfile(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token,
            @PathVariable UUID userId,
            @RequestBody ProfileUpdateRequest request) {

        return validateToken(token)
                .flatMap(validatedUserId -> {
                    if (!userId.toString().equals(validatedUserId)) {
                        return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build());
                    }

                    try {
                        Profile updatedProfile = profileService.updateProfile(userId, request);
                        return Mono.just(ResponseEntity.ok(updatedProfile));
                    } catch (RuntimeException e) {
                        return Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND).build());
                    }
                })
                .switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()));
    }
}

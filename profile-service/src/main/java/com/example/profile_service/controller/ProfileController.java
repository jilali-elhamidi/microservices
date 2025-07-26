package com.example.profile_service.controller;

import com.example.profile_service.dto.ProfileUpdateRequest;
import com.example.profile_service.model.Profile;
import com.example.profile_service.service.ProfileService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.UUID;

@RestController
@RequestMapping("/profiles")
public class ProfileController {

    private final ProfileService profileService;
    private final WebClient.Builder webClientBuilder;

    @Value("${auth-service.url}")
    private String authServiceUrl;

    public ProfileController(ProfileService profileService, WebClient.Builder webClientBuilder) {
        this.profileService = profileService;
        this.webClientBuilder = webClientBuilder;
    }

    private Mono<String> validateToken(String token) {
        WebClient webClient = webClientBuilder.build();
        return webClient.get()
                .uri(authServiceUrl + "/auth/validateToken")
                .header(HttpHeaders.AUTHORIZATION, token)
                .retrieve()
                .bodyToMono(String.class);
    }

    @GetMapping("/{userId}")
    public Mono<ResponseEntity<Profile>> getProfile(@RequestHeader("Authorization") String token, @PathVariable UUID userId) {
        return validateToken(token)
                .flatMap(validatedUserId -> {
                    if (!validatedUserId.equals(userId.toString())) {
                        return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build());
                    }
                    return Mono.justOrEmpty(profileService.getProfileByUserId(userId))
                            .map(ResponseEntity::ok)
                            .defaultIfEmpty(ResponseEntity.notFound().build());
                });
    }

    @PutMapping("/{userId}")
    public Mono<ResponseEntity<Profile>> updateProfile(@RequestHeader("Authorization") String token, @PathVariable UUID userId, @RequestBody ProfileUpdateRequest request) {
        return validateToken(token)
                .flatMap(validatedUserId -> {
                    if (!validatedUserId.equals(userId.toString())) {
                        return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build());
                    }
                    try {
                        Profile updatedProfile = profileService.updateProfile(userId, request);
                        return Mono.just(ResponseEntity.ok(updatedProfile));
                    } catch (RuntimeException e) {
                        return Mono.just(ResponseEntity.notFound().build());
                    }
                });
    }
}
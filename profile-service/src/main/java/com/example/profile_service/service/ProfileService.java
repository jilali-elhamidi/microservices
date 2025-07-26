package com.example.profile_service.service;

import com.example.profile_service.dto.ProfileUpdateRequest;
import com.example.profile_service.model.Profile;
import com.example.profile_service.repository.ProfileRepository;
import org.springframework.stereotype.Service;
import java.util.Optional;
import java.util.UUID;

@Service
public class ProfileService {

    private final ProfileRepository profileRepository;

    public ProfileService(ProfileRepository profileRepository) {
        this.profileRepository = profileRepository;
    }

    public Optional<Profile> getProfileByUserId(UUID userId) {
        return profileRepository.findByUserId(userId);
    }

    public Profile updateProfile(UUID userId, ProfileUpdateRequest request) {
        Profile profile = profileRepository.findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("Profile not found"));

        if (request.getFirstName() != null) {
            profile.setFirstName(request.getFirstName());
        }
        if (request.getLastName() != null) {
            profile.setLastName(request.getLastName());
        }
        if (request.getBio() != null) {
            profile.setBio(request.getBio());
        }

        return profileRepository.save(profile);
    }
}
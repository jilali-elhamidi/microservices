package com.example.profile_service.event;

import com.example.profile_service.model.Profile;
import com.example.profile_service.repository.ProfileRepository;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class UserRegisteredEventConsumer {

    private final ProfileRepository profileRepository;

    public UserRegisteredEventConsumer(ProfileRepository profileRepository) {
        this.profileRepository = profileRepository;
    }

    @RabbitListener(queues = "user_registration_queue")
    // CORRECTION ICI : Utiliser la classe UserRegisteredEvent définie LOCALEMENT dans ce microservice
    public void handleUserRegistration(UserRegisteredEvent event) { // Importe et utilise la classe UserRegisteredEvent du package actuel
        try {
            // Accéder directement à l'UUID et l'email depuis l'objet event
            UUID userId = event.getUserId();
            String email = event.getEmail();

            System.out.println("Received user registration event for userId: " + userId + " with email: " + email);

            Profile profile = new Profile();
            profile.setUserId(userId);
            // Vous pouvez initialiser d'autres champs du profil ici si l'événement les contient
            profileRepository.save(profile);

            System.out.println("Created new profile for userId: " + userId);
        } catch (Exception e) {
            System.err.println("Error processing user registration event: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

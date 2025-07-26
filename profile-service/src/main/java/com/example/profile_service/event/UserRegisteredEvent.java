package com.example.profile_service.event; // Notez le package du profile-service

import lombok.Data;
import java.util.UUID;

@Data
public class UserRegisteredEvent {
    private UUID userId;
    private String email;
}

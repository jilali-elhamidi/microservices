package com.example.auth_service.event;

import lombok.Data;
import java.util.UUID;

@Data
public class UserRegisteredEvent {
    private UUID userId;
    private String email;
}
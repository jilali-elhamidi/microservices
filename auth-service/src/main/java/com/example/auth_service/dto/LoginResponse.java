package com.example.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor; // Ajouté pour la désérialisation JSON

@Data
@AllArgsConstructor
@NoArgsConstructor // Ajouté pour la désérialisation JSON
public class LoginResponse {
    private String accessToken;
    private String refreshToken;
    private boolean requires2Fa; // Nouveau champ
}

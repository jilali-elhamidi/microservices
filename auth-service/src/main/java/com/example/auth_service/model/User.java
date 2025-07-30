package com.example.auth_service.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime; // Import pour LocalDateTime
import java.util.UUID;

@Entity
@Table(name = "users")
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = true)
    private String hashedRefreshToken;

    // Champs pour le 2FA (déjà ajoutés)
    @Column(name = "is_2fa_enabled", nullable = false)
    private boolean is2faEnabled = false;

    @Column(name = "two_fa_secret", nullable = true)
    private String twoFaSecret;

    // Champs pour la limitation des tentatives de connexion et le verrouillage de compte
    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts = 0;

    @Column(name = "account_locked", nullable = false)
    private boolean accountLocked = false;

    @Column(name = "lock_time")
    private LocalDateTime lockTime; // Quand le compte a été verrouillé
}

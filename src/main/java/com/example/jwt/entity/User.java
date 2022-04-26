package com.example.jwt.entity;

import com.example.jwt.config.oauth.AuthProvider;
import lombok.*;

import javax.persistence.*;

@Builder
@Getter
@AllArgsConstructor(access = AccessLevel.PROTECTED)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id", nullable = false)
    private long id;

    private String name;

    @Column(name = "email", length = 200, nullable = false)
    private String email;

    @Column(name = "password")
    private String password;

    @Enumerated(value = EnumType.STRING)
    private AuthProvider authProvider;

    public void update(String name, String email) {
        this.name = name;
        this.email = email;
    }
}

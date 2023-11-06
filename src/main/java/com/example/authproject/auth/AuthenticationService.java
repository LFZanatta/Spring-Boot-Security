package com.example.authproject.auth;

import com.example.authproject.config.JWTService;
import com.example.authproject.user.Role;
import com.example.authproject.user.User;
import com.example.authproject.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;

    private final PasswordEncoder passwordEncoder;

    private final JWTService jwtService;

    private final AuthenticationManager authManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder().name(request.getName()).lastName(request.getLastName())
                .email(request.getEmail()).password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER).build();

        repository.save(user);
        var jwtToken =  jwtService.generateTokenFromUser(user);

        return AuthenticationResponse.builder().token(jwtToken).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(),
                request.getPassword()));

        var user = repository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken =  jwtService.generateTokenFromUser(user);

        return AuthenticationResponse.builder().token(jwtToken).build();
    }
}

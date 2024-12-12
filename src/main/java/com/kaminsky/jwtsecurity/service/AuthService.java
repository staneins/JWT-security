package com.kaminsky.jwtsecurity.service;

import com.kaminsky.jwtsecurity.dto.UserDTO;
import com.kaminsky.jwtsecurity.entity.User;
import com.kaminsky.jwtsecurity.repository.UserRepository;
import com.kaminsky.jwtsecurity.utils.JWTUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final JWTUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthService(UserRepository userRepository, JWTUtils jwtUtils, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.jwtUtils = jwtUtils;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    public UserDTO signUp(UserDTO registration) {
        UserDTO response = new UserDTO();
        try {
            User user = new User();
            user.setUsername(registration.getUsername());
            user.setPassword(passwordEncoder.encode(registration.getPassword()));
            user.setRole(registration.getRole());

            User resultUser = userRepository.save(user);

            if (resultUser != null && resultUser.getId() > 0) {
                response.setUser(resultUser);
                response.setMessage("User saved successfully");
                response.setStatusCode(200);
            }
        } catch (Exception e) {
                response.setStatusCode(500);
                response.setError(e.getMessage());
        }
        return response;
    }

    public UserDTO signIn(UserDTO request) {
        UserDTO response = new UserDTO();
        try {
            var user = userRepository.findByUsername(request.getUsername()).orElseThrow();

            if (!user.isAccountNonLocked()) {
                response.setStatusCode(403);
                response.setError("Account is locked due to multiple failed login attempts.");
                return response;
            }

            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

            user.setFailedAttempts(0);
            userRepository.save(user);

            var jwt = jwtUtils.generateToken(user);
            var refreshToken = jwtUtils.generateRefreshToken(new HashMap<>(), user);
            response.setStatusCode(200);
            response.setToken(jwt);
            response.setRefreshToken(refreshToken);
            response.setExpirationTime("24Hr");
            response.setMessage("Successfully signed in");
        } catch (Exception e) {
            User user = userRepository.findByUsername(request.getUsername()).orElseThrow();
            user.setFailedAttempts(user.getFailedAttempts() + 1);

            if (user.getFailedAttempts() >= 5) {
                user.setAccountLocked(true);
            }

            userRepository.save(user);

            response.setStatusCode(500);
            response.setError(e.getMessage());
        }
        return response;
    }

    public UserDTO refreshToken(UserDTO request) {
        UserDTO response = new UserDTO();
        String username = jwtUtils.extractUsername(request.getUsername());
        User user = userRepository.findByUsername(username).orElseThrow();

        if (jwtUtils.isTokenValid(request.getRefreshToken(), user)) {
            var jwt = jwtUtils.generateToken(user);
            response.setStatusCode(200);
            response.setToken(jwt);
            response.setRefreshToken(request.getRefreshToken());
            response.setExpirationTime("24Hr");
            response.setMessage("Successfully refreshed token");
        }
        response.setStatusCode(500);
        return response;
    }
}

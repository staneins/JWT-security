package com.kaminsky.jwtsecurity.service;

import com.kaminsky.jwtsecurity.dto.UserDTO;
import com.kaminsky.jwtsecurity.entity.User;
import com.kaminsky.jwtsecurity.repository.UserRepository;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public List<UserDTO> getAllUsers() {
        return userRepository.findAll().stream().map(this::mapToDTO).collect(Collectors.toList());
    }

    public UserDTO getCurrentUser() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
        return mapToDTO(user);
    }

    public UserDTO updateUserProfile(UserDTO userUpdateRequest) {
        User user = userRepository.findByUsername(userUpdateRequest.getUsername()).orElseThrow(() -> new RuntimeException("User not found"));

        if (userUpdateRequest.getPassword() != null) {
            user.setPassword(passwordEncoder.encode(userUpdateRequest.getPassword()));
        }
        if (userUpdateRequest.getRole() != null) {
            user.setRole(userUpdateRequest.getRole());
        }

        User updatedUser = userRepository.save(user);
        return mapToDTO(updatedUser);
    }

    public void blockUser(String username) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
        user.setAccountLocked(true);
        userRepository.save(user);
    }

    public void unblockUser(String username) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
        user.setAccountLocked(false);
        userRepository.save(user);
    }

    public void deleteUser(Long userId) {
        userRepository.deleteById(userId);
    }

    private UserDTO mapToDTO(User user) {
        UserDTO dto = new UserDTO();
        dto.setUsername(user.getUsername());
        dto.setRole(user.getRole());
        dto.setAccountNonLocked(user.isAccountNonLocked());
        return dto;
    }
}


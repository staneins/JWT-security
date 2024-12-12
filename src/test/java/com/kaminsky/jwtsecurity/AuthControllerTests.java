package com.kaminsky.jwtsecurity;

import com.kaminsky.jwtsecurity.controller.AuthController;
import com.kaminsky.jwtsecurity.dto.UserDTO;
import com.kaminsky.jwtsecurity.service.AuthService;
import com.kaminsky.jwtsecurity.service.OurUserDetailedService;
import com.kaminsky.jwtsecurity.utils.JWTUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
public class AuthControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @MockBean
    private JWTUtils jwtUtils;

    @MockBean
    private OurUserDetailedService ourUserDetailedService;

    @Test
    public void testSignUp() throws Exception {
        UserDTO signUpRequest = new UserDTO();
        signUpRequest.setUsername("newuser");
        signUpRequest.setPassword("newpassword");

        UserDTO signUpResponse = new UserDTO();
        signUpResponse.setStatusCode(200);
        signUpResponse.setMessage("User successfully registered");

        when(authService.signUp(signUpRequest)).thenReturn(signUpResponse);

        mockMvc.perform(post("https://localhost:8443/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"newuser\", \"password\":\"newpassword\"}"))
                .andExpect(status().isOk())  // Ожидаем статус 200 OK
                .andExpect(jsonPath("$.statusCode").value(200))
                .andExpect(jsonPath("$.message").value("User successfully registered"));
    }

    @Test
    public void testSignIn() throws Exception {
        UserDTO signInRequest = new UserDTO();
        signInRequest.setUsername("admin");
        signInRequest.setPassword("admin");

        UserDTO signInResponse = new UserDTO();
        signInResponse.setStatusCode(200);
        signInResponse.setMessage("Successfully signed in");
        signInResponse.setToken("mocked_jwt_token");

        when(authService.signIn(signInRequest)).thenReturn(signInResponse);

        mockMvc.perform(post("https://localhost:8443/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"admin\", \"password\":\"admin\"}"))
                .andExpect(status().isOk())  // Ожидаем статус 200 OK
                .andExpect(jsonPath("$.statusCode").value(200))
                .andExpect(jsonPath("$.message").value("Successfully signed in"))
                .andExpect(jsonPath("$.token").value("mocked_jwt_token"));
    }

    @Test
    public void testRefreshToken() throws Exception {
        UserDTO refreshRequest = new UserDTO();
        refreshRequest.setToken("mocked_refresh_token");

        UserDTO refreshResponse = new UserDTO();
        refreshResponse.setStatusCode(200);
        refreshResponse.setMessage("Token successfully refreshed");
        refreshResponse.setToken("mocked_new_jwt_token");

        when(authService.refreshToken(refreshRequest)).thenReturn(refreshResponse);

        mockMvc.perform(post("https://localhost:8443/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"mocked_refresh_token\"}"))
                .andExpect(status().isOk())  // Ожидаем статус 200 OK
                .andExpect(jsonPath("$.statusCode").value(200))
                .andExpect(jsonPath("$.message").value("Token successfully refreshed"))
                .andExpect(jsonPath("$.token").value("mocked_new_jwt_token"));
    }
}

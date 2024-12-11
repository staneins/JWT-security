package com.kaminsky.jwtsecurity.config;

import com.kaminsky.jwtsecurity.service.OurUserDetailedService;
import com.kaminsky.jwtsecurity.utils.JWTUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private final JWTUtils jwtUtils;
    private OurUserDetailedService ourUserDetailedService;

    public JWTAuthenticationFilter(JWTUtils jwtUtils, OurUserDetailedService ourUserDetailedService) {
        this.jwtUtils = jwtUtils;
        this.ourUserDetailedService = ourUserDetailedService;
    }

    // Метод, выполняемый для каждого HTTP запроса
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwtToken;
        final String username;

        if (authHeader == null || authHeader.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        jwtToken = authHeader.substring(7);
        username = jwtUtils.extractUsername(jwtToken);

        if (username == null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = ourUserDetailedService.loadUserByUsername(username);
            if (jwtUtils.isTokenValid(jwtToken, userDetails)) {
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                context.setAuthentication(token);
                SecurityContextHolder.setContext(context);
            }
        }

        // Шаг 1: Извлечение заголовка авторизации из запроса

        // Шаг 2: Проверка наличия заголовка авторизации

        // Шаг 3: Извлечение токена из заголовка

        // Шаг 4: Извлечение имени пользователя из JWT токена

        // Шаг 5: Проверка валидности токена и аутентификации

        // Шаг 6: Создание нового контекста безопасности

        // Шаг 7: Передача запроса на дальнейшую обработку в фильтрующий цепочке
    }

}

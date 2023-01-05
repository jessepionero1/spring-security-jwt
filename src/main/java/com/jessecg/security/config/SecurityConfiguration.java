package com.jessecg.security.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf()
                .disable() // Desabilita a proteção CSRF (Cross-Site Request Forgery) para esta aplicação.
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/auth/**") // Permite que todas as requisições que correspondam ao padrão de URL "/api/v1/auth/**" sejam permitidas sem autenticação.
                .permitAll()
                .anyRequest() // Exige que todas as outras requisições estejam autenticadas.
                .authenticated()
                .and()
                .sessionManagement() // Define a política de criação de sessão como "STATELESS", o que significa que nenhuma sessão será criada nesta aplicação.
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider) // Define o provedor de autenticação para esta aplicação.
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class); // Adiciona um filtro JWT antes do filtro de autenticação de nome de usuário e senha na cadeia de filtros de segurança.

        return http.build(); // Constroi e retorna a cadeia de filtros de segurança configurada.
    }
}
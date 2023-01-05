package com.jessecg.security.config;

import com.jessecg.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Classe de configuração da aplicação.
 */
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    /**
     * Repositório de usuários.
     */
    private final UserRepository userRepository;

    /**
     * Cria um serviço de detalhes do usuário usando o repositório de usuários.
     *
     * @return serviço de detalhes do usuário
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    /**
     * Cria um provedor de autenticação baseado em dados de autenticação de acesso a dados (DAO).
     *
     * @return provedor de autenticação baseado em DAO
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * Cria um gerenciador de autenticação usando a configuração de autenticação especificada.
     *
     * @param config configuração de autenticação
     * @return gerenciador de autenticação
     * @throws Exception caso ocorra algum erro ao criar o gerenciador de autenticação
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Cria um codificador de senha do BCrypt.
     *
     * @return codificador de senha do BCrypt
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
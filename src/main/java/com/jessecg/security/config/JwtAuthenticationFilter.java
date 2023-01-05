package com.jessecg.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {


    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;



    /**
     * Método que sobrescreve o método doFilterInternal da classe pai.
     * É chamado pela classe pai quando é necessário filtrar solicitações e respostas HTTP.
     *
     * @param request objeto HttpServletRequest que representa a solicitação HTTP
     * @param response objeto HttpServletResponse que representa a resposta HTTP
     * @param filterChain objeto FilterChain que representa a cadeia de filtros através da qual a solicitação é processada
     * @throws ServletException se ocorrer algum erro durante o processamento da solicitação
     * @throws IOException se ocorrer algum erro de entrada/saída durante o processamento da solicitação
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Obtém o cabeçalho "Authorization" da solicitação
        final String authHeader = request.getHeader("Authorization");

        // Verifica se o cabeçalho começa com "Bearer " (indicando que um JWT segue)
        final String jwt;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // Se o cabeçalho não existir ou não começar com "Bearer ", prossegue com o próximo filtro
            filterChain.doFilter(request, response);
            return;
        }

        // Extrai o JWT do cabeçalho
        jwt = authHeader.substring(7);
        // Extrai o email do usuário do JWT
        userEmail = jwtService.extractUsername(jwt);

        // Se o email do usuário for encontrado e não houver autenticação atual no Spring Security...
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // ...carrega os detalhes do usuário com base no email...
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            // ...e verifica se o JWT é válido para os detalhes do usuário
            if (jwtService.isTokenValid(jwt, userDetails)) {
                // Se o JWT for válido, cria um novo objeto de autenticação do Spring Security com os detalhes do usuário...
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
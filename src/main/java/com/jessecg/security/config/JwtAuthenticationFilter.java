package com.jessecg.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {


    private final JwtService jwtService;


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

            //"A anotação @NonNull da biblioteca org.springframework.lang é uma anotação de validação que é usada para indicar que um parâmetro ou um valor de retorno não pode ser null."
          @NonNull HttpServletRequest request,
          @NonNull  HttpServletResponse response,
          @NonNull  FilterChain filterChain)
            throws ServletException, IOException {
            final String authHeader = request.getHeader("Authorizacion");
            final String jwt;
            final String userEmail;
            if(authHeader == null || !authHeader.startsWith("Bearer ")){
                filterChain.doFilter(request, response);
                return;
            }
            jwt = authHeader.substring(7);
            userEmail = jwtService.extractUsername(jwt); // todo extract the userEmail from JWT token;


    }

}

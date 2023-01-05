package com.jessecg.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Classe de serviço responsável por gerar, extrair e validar JWTs (JSON Web Tokens).
 */
@Service
public class JwtService {

    /**
     * Chave privada usada para assinar o JWT.
     */
    private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";

    /**
     * Extrai o nome de usuário (em inglês, "subject") do JWT.
     *
     * @param token JWT a ser analisado
     * @return nome de usuário presente no JWT
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extrai uma afirmação (claim) do JWT.
     *
     * @param token JWT a ser analisado
     * @param claimsResolver função que determina qual afirmação deve ser extraída do JWT
     * @param <T> tipo da afirmação a ser extraída
     * @return afirmação presente no JWT
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Gera um novo JWT com os detalhes do usuário especificado.
     *
     * @param userDetails detalhes do usuário a serem inseridos no JWT
     * @return novo JWT com os detalhes do usuário
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Gera um novo JWT com os detalhes do usuário especificado e as afirmações (claims) extras especificadas.
     *
     * @param extraClaims afirmações (claims) extras a serem inseridas no JWT
     * @param userDetails detalhes do usuário a serem inseridos no JWT
     * @return novo JWT com os detalhes do usuário e as afirmações (claims) extras
     */
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Verifica se um JWT é válido para os detalhes do usuário especificado.
     *
     * @param token JWT a ser analisado
     * @param userDetails detalhes do usuário a serem usados para a validação
     * @return verdadeiro se o JWT for válido para os detalhes do usuário, falso caso contrário
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Verifica se um JWT expirou.
     *
     * @param token JWT a ser analisado
     * @return verdadeiro se o JWT já expirou, falso caso contrário
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Extrai a data de expiração de um JWT.
     *
     * @param token JWT a ser analisado
     * @return data de expiração presente no JWT
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extrai todas as afirmações (claims) de um JWT.
     *
     * @param token JWT a ser analisado
     * @return todas as afirmações presentes no JWT
     */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Retorna a chave (key) usada para assinar o JWT.
     *
     * @return chave (key) usada para assinar o JWT
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}

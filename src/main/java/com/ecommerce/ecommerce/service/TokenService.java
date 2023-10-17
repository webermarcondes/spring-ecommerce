package com.ecommerce.ecommerce.service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.ecommerce.ecommerce.model.UsuarioEntity;

@Service
public class TokenService {

    @Value("${api.security.token.secret}") //gerador de palavra secreta usada para criar o token
    private String secret; //Variável que armazena a palavra secreta usada para criar o token;

    public String generateToken(UsuarioEntity usuario){
        try{
            Algorithm algoritmo = Algorithm.HMAC256(secret); //Gera uma hash com o secret;
            String token = JWT.create()
                .withIssuer("ecommerce-senac")  //"issuer" é a nossa palavra secreta usada na token;
                .withSubject(usuario.getEmail())      //"Subject" é o assunto
                .withExpiresAt(genExpirationDate())  //Data de expiração do token
                .sign(algoritmo);  //"assinatura" da token, que seria a hash gerada;
            return token;
        }catch(JWTCreationException exception){
            throw new RuntimeException("Erro na geração do token", exception);
        }
    }

    private Instant genExpirationDate(){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }

    public String validateToken(String token){
        try{
            
            Algorithm algoritmo = Algorithm.HMAC256(secret);
            return JWT.require(algoritmo)
                .withIssuer("ecommerce-senac")
                .build()
                .verify(token) //verifica se o token passado é igual ao gerado;
                .getSubject();  //verifica se os e-mails são os mesmos;
        }catch(JWTVerificationException exception){
            return "";
        }
    }


    public String getToken(String a) {
        return a;
    }
}
package com.ecommerce.ecommerce.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration   //define a classe como uma classe de configuração
@EnableWebSecurity //Permite a classe realizar a configuração das rotas na web
public class SecurityConfigurations implements WebMvcConfigurer {

    @Autowired //Injeção de dependências
    SecurityFilter security_filter;


    @Bean
    public SecurityFilterChain SecurityFilterChain (HttpSecurity http_security) throws Exception {
        return  http_security                
                .csrf(csrf -> csrf.disable())                
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize  //Quais as requisições HTTP que serão autorizadas
                    .requestMatchers(HttpMethod.POST, "/auth").permitAll()
                    .requestMatchers(HttpMethod.GET, "/").permitAll()
                    .requestMatchers(HttpMethod.POST, "/usuario/salvar").permitAll()
                    .anyRequest().authenticated()
                    
                )                                
                .addFilterBefore(security_filter, UsernamePasswordAuthenticationFilter.class)
                .build(); //Filtro antes de começar os códigos acima para verificar se o token gerado é o correto.
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration auth_config)
    throws Exception {
        return auth_config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
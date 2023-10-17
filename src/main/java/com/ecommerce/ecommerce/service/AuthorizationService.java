package com.ecommerce.ecommerce.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.ecommerce.ecommerce.repository.UsuarioRepository;


@Service
public class AuthorizationService implements UserDetailsService {

    @Autowired
    UsuarioRepository usuario_repositorio;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // TODO Auto-generated method stub
        return usuario_repositorio.findByEmail(email);
    }
    
}
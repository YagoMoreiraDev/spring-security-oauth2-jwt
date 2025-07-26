package com.devsuperior.demo.services;

import com.devsuperior.demo.entities.Role;
import com.devsuperior.demo.entities.User;
import com.devsuperior.demo.projection.UserDetailsProjection;
import com.devsuperior.demo.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        List<UserDetailsProjection> userDetailsProjections = userRepository.searchUserAndRolesByEmail(username);
        if(userDetailsProjections.isEmpty()) {
            throw new UsernameNotFoundException("Usuário não existe");
        }

        User user = new User();
        user.setEmail(username);
        user.setPassword(userDetailsProjections.getFirst().getPassword());

        for(UserDetailsProjection userProjection : userDetailsProjections) {
            user.addRole(new Role(userProjection.getRoleId(), userProjection.getAuthority()));
        }

        return user;
    }
}

package ro.upb.acs.worldcuptickets.authservice.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import ro.upb.acs.worldcuptickets.authservice.entity.Role;
import ro.upb.acs.worldcuptickets.authservice.repository.UserRepository;

@Service
public class JpaUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public JpaUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
            .map(user -> org.springframework.security.core.userdetails.User
                    .withUsername(user.getUsername())
                    .password(user.getPassword())
                    .roles(String.valueOf(user.getRoles().stream().map(Role::getName)))
                    .build())
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }
}

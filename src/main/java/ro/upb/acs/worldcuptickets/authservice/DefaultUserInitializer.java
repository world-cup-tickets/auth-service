package ro.upb.acs.worldcuptickets.authservice;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import ro.upb.acs.worldcuptickets.authservice.entity.Role;
import ro.upb.acs.worldcuptickets.authservice.entity.User;
import ro.upb.acs.worldcuptickets.authservice.repository.RoleRepository;
import ro.upb.acs.worldcuptickets.authservice.repository.UserRepository;

import java.util.Collections;

@Component
public class DefaultUserInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public DefaultUserInitializer(UserRepository userRepository, RoleRepository roleRepository,
                                  PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        String defaultUsername = "user";
        String defaultPassword = "password";
        String defaultRoleName = "ADMIN";

        if (userRepository.findByUsername(defaultUsername).isEmpty()) {
            Role role = roleRepository.findByName(defaultRoleName)
                .orElseGet(() -> {
                    Role newRole = new Role();
                    newRole.setName(defaultRoleName);
                    return roleRepository.save(newRole);
                });

            User user = new User();
            user.setUsername(defaultUsername);
            user.setPassword(passwordEncoder.encode(defaultPassword));
            user.setRoles(Collections.singleton(role));
            userRepository.save(user);
        }
    }
}
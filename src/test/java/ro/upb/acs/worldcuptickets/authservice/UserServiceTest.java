package ro.upb.acs.worldcuptickets.authservice;

import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.crypto.password.PasswordEncoder;

import ro.upb.acs.worldcuptickets.authservice.entity.User;
import ro.upb.acs.worldcuptickets.authservice.repository.UserRepository;
import ro.upb.acs.worldcuptickets.authservice.service.UserService;

class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void createUser_ShouldSaveUserWithEncodedPassword() {
        String username = "testuser";
        String rawPassword = "password123";
        String encodedPassword = "encodedPassword123";

        when(passwordEncoder.encode(rawPassword)).thenReturn(encodedPassword);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        userService.createUser(username, rawPassword);

        verify(passwordEncoder).encode(rawPassword);
        verify(userRepository).save(any(User.class));
    }
}
package security.oauth2;


import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

import static org.springframework.security.core.userdetails.User.withUsername;

@Component
@AllArgsConstructor
public class EjarDetailsService implements UserDetailsService {



    private BrokerRepository brokerRepository;



    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Broker broker = brokerRepository.findByUsername(s).orElseThrow(() ->
                new UsernameNotFoundException(String.format("User with name %s does not exist", s)));

        return withUsername(broker.getUsername())
                .password(broker.getPassword())
                .authorities(broker.getRoles())
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .disabled(false)
                .build();
    }


}

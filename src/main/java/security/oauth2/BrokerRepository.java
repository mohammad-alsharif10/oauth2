package security.oauth2;


import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface BrokerRepository extends JpaRepository<Broker, Long> {


    Optional<Broker> findByUsername(String username);
}

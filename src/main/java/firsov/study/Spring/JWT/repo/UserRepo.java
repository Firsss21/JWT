package firsov.study.Spring.JWT.repo;

import firsov.study.Spring.JWT.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface UserRepo extends JpaRepository<User, Long> {
    User findByUsername(String username);

    void deleteAll();
}

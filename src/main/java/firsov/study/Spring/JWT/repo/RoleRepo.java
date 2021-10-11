package firsov.study.Spring.JWT.repo;

import firsov.study.Spring.JWT.domain.Role;
import firsov.study.Spring.JWT.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String username);
    void deleteAll();
}

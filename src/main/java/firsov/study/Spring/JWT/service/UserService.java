package firsov.study.Spring.JWT.service;

import firsov.study.Spring.JWT.domain.Role;
import firsov.study.Spring.JWT.domain.User;
import org.springframework.stereotype.Service;

import java.util.List;


public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUsers();
    void clearUsers();
}

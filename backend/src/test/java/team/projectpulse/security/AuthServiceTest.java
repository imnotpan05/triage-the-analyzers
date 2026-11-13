package team.projectpulse.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import team.projectpulse.instructor.Instructor;
import team.projectpulse.instructor.converter.InstructorToInstructorDtoConverter;
import team.projectpulse.instructor.dto.InstructorDto;
import team.projectpulse.student.Student;
import team.projectpulse.student.converter.StudentToStudentDtoConverter;
import team.projectpulse.student.dto.StudentDto;
import team.projectpulse.user.MyUserPrincipal;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private JwtProvider jwtProvider;

    @Mock
    private StudentToStudentDtoConverter studentToStudentDtoConverter;

    @Mock
    private InstructorToInstructorDtoConverter instructorToInstructorDtoConverter;

    @InjectMocks
    private AuthService authService;

    @Test
    void createLoginInfoRecognizesStudentRoleWhenItAppearsWithOtherRoles() {
        Student student = new Student("sally", "Sally", "Student", "sally@example.com", "pass123", true, "student admin");
        student.setId(7);

        Authentication authentication = mock(Authentication.class);
        MyUserPrincipal principal = new MyUserPrincipal(student);
        StudentDto studentDto = new StudentDto(7, "sally", "Sally", "Student", "sally@example.com", true, "student admin", 3, "Intro to CS", 9, "Team 1");
        Collection authorities = List.of(
                new SimpleGrantedAuthority("ROLE_student"),
                new SimpleGrantedAuthority("ROLE_admin")
        );

        given(authentication.getPrincipal()).willReturn(principal);
        given(authentication.getName()).willReturn("sally");
        given(authentication.getAuthorities()).willReturn(authorities);
        given(jwtProvider.createToken(authentication)).willReturn("token-123");
        given(studentToStudentDtoConverter.convert(student)).willReturn(studentDto);

        Map<String, Object> result = this.authService.createLoginInfo(authentication);

        assertThat(result).containsEntry("token", "token-123");
        assertThat(result).containsKey("userInfo");
        assertThat(result.get("userInfo")).isEqualTo(studentDto);
    }

    @Test
    void createLoginInfoRecognizesInstructorRoleWhenItAppearsWithOtherRoles() {
        Instructor instructor = new Instructor("prof", "Prof", "Smith", "prof@example.com", "pass123", true, "instructor admin");
        instructor.setId(11);

        Authentication authentication = mock(Authentication.class);
        MyUserPrincipal principal = new MyUserPrincipal(instructor);
        InstructorDto instructorDto = new InstructorDto(11, "prof", "Prof", "Smith", "prof@example.com", true, "instructor admin", 2, 3);
        Collection authorities = List.of(
                new SimpleGrantedAuthority("ROLE_instructor"),
                new SimpleGrantedAuthority("ROLE_admin")
        );

        given(authentication.getPrincipal()).willReturn(principal);
        given(authentication.getName()).willReturn("prof");
        given(authentication.getAuthorities()).willReturn(authorities);
        given(jwtProvider.createToken(authentication)).willReturn("token-456");
        given(instructorToInstructorDtoConverter.convert(instructor)).willReturn(instructorDto);

        Map<String, Object> result = this.authService.createLoginInfo(authentication);

        assertThat(result).containsEntry("token", "token-456");
        assertThat(result).containsKey("userInfo");
        assertThat(result.get("userInfo")).isEqualTo(instructorDto);
    }
}

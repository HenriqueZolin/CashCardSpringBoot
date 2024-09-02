package example.cashcard;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

//Fala pro spring para usar esta classe para configurar o spring e o spring boot
@Configuration
class SecurityConfig {

    //precisa de um bean para configurar o FIlter Chain
    //FIlter Chain define uma cadeia d emetodos que serao executados, cada metodo vai definir uma "Camada" da segurança
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/cashcards/**").hasRole("CARD-OWNER"))
                .httpBasic(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable());
        //Todos os HTTP requests para cashcards/ e seus endpoints estao precisando de autenticação HTTP Basic Authentication Security
        //
        //Also, do not require CSRF security.

        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsService testOnlyUsers(PasswordEncoder passwordEncoder) {
        User.UserBuilder users = User.builder();
        //co nfigura um usuario chamado sarah1 com senha abc123
        UserDetails sarah = users
                .username("sarah1")
                .password(passwordEncoder.encode("abc123"))
                .roles("CARD-OWNER") // No roles for now
                .build();

        UserDetails hankOwnsNoCards = users
                .username("hank-owns-no-cards")
                .password(passwordEncoder.encode("qrs456"))
                .roles("NON-OWNER") // new role
                .build();

        return new InMemoryUserDetailsManager(sarah, hankOwnsNoCards);
    }
}

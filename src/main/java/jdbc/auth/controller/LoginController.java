package jdbc.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jdbc.auth.form.SignInForm;
import jdbc.auth.form.SignInResponse;
import jdbc.auth.util.JwtUtil;

@RestController
public class LoginController {

	@Autowired
	private UserDetailsService userDetailsService;
	@Autowired
	private JwtUtil jwtUtil;
	@Autowired
	AuthenticationManager authManager;

	@PostMapping("authenticate")
	public ResponseEntity<?> authenticate(@RequestBody SignInForm signInForm) throws Exception{
		// Accepts User Id and Password
		// Returns JWT as response
		
		try {
			authManager.authenticate(new UsernamePasswordAuthenticationToken(signInForm.getEmail(), signInForm.getPassword()));
		}
		catch(BadCredentialsException e) {
			throw new Exception("Incorrect username or password");
		}
		
		final UserDetails userDetails = userDetailsService.loadUserByUsername(signInForm.getEmail());
		final String jwt = jwtUtil.generateToken(userDetails);
		
		return ResponseEntity.ok(new SignInResponse(jwt));
	}
}

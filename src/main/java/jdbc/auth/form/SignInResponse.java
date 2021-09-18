package jdbc.auth.form;

public class SignInResponse {

	private final String jwt;

	public SignInResponse(String jwt) {
		super();
		this.jwt = jwt;
	}

	public String getJwt() {
		return jwt;
	}

}

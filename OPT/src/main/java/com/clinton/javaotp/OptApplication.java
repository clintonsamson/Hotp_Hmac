package com.clinton.javaotp;

import java.nio.charset.StandardCharsets;
import java.security.Key;

import javax.annotation.PostConstruct;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class OptApplication {

	private Key HOTP_KEY = new SecretKeySpec("12345678901234567890".getBytes(StandardCharsets.US_ASCII),
			"RAW");

	public static void main(String[] args) {
		SpringApplication.run(OptApplication.class, args);
	}

	@PostConstruct
	private void init() {
		try {
			HmacOneTimePasswordGenerator hmac = new HmacOneTimePasswordGenerator(6, "HmacSHA1");
			int otp = hmac.generateOneTimePassword(HOTP_KEY, 1);
			System.err.println("OTP-" + otp);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}

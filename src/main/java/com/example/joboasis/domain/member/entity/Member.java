package com.example.joboasis.domain.member.entity;

import com.example.joboasis.domain.member.enums.MemberJob;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Member {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "member_id")
	private Long id;
	private String name;
	private String email;
	private String password;
	private String phoneNumber;
	@Enumerated(EnumType.STRING)
	private MemberJob job;
	private String authority;

	public Member(String email, String authority) {
		this.email = email;
		this.password = "password";  //Password for authentication in JWTValidator
		this.authority = authority;
	}

	@Builder
	public Member(String name, String email, String password, String phoneNumber, MemberJob job) {
		this.name = name;
		this.email = email;
		this.password = password;
		this.phoneNumber = phoneNumber;
		this.job = job;
		this.authority = "ROLE_MEMBER";
	}

}

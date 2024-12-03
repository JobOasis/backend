package com.example.joboasis.domain.member.dto;

import com.example.joboasis.domain.member.entity.Member;
import com.example.joboasis.domain.member.enums.MemberJob;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class MemberRequestDto {

    private String email;
    private String password;
    private String name;
    private String phoneNumber;
    private MemberJob job;

    public Member toEntity(String encodedPassword) {
        return Member.builder()
                .name(name)
                .email(email)
                .password(encodedPassword)
                .phoneNumber(phoneNumber)
                .job(job)
                .build();
    }


}

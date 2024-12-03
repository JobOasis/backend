package com.example.joboasis.domain.member.service;

import com.example.joboasis.domain.member.dto.MemberRequestDto;
import com.example.joboasis.domain.member.entity.Member;
import com.example.joboasis.domain.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    public boolean checkEmail(String email) {
        return memberRepository.existsByEmail(email);
    }

    @Transactional  //정상 이메일 인증 후에만 가입 가능
    public Long addMember(MemberRequestDto memberDto) {
        String encodedPassword = passwordEncoder.encode(memberDto.getPassword());
        Member member = memberDto.toEntity(encodedPassword);
        Member savedMember = memberRepository.save(member);

        return savedMember.getId();
    }
}

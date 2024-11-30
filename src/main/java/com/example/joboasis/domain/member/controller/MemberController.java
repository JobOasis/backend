package com.example.joboasis.domain.member.controller;

import com.example.joboasis.domain.member.dto.MemberRequestDto;
import com.example.joboasis.domain.member.service.MailService;
import com.example.joboasis.domain.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;
    private final MailService mailService;

    @PostMapping("/signup/check-email")  //이메일 중복 확인
    public boolean checkEmail(@RequestParam String email) {
        return memberService.checkEmail(email);
    }

    @PostMapping("/signup/send-email-code")  //인증번호 받기 버튼 클릭 -> 인증번호 메일 전송
    public void sendEmailCode(@RequestParam String email) {
        mailService.sendMail(email);
    }

    @PostMapping("/signup/verify-email")  //인증번호 확인
    public boolean verifyEmail(@RequestParam String verificationCode,
                               @RequestParam String email) {
        return mailService.checkVerificationCode(email, verificationCode);
    }

    @PostMapping("/signup")
    public ResponseEntity addMember(@RequestBody MemberRequestDto memberDto) {
        Long memberId = memberService.addMember(memberDto);
        return new ResponseEntity<>(memberId, HttpStatus.CREATED);
    }

    @GetMapping("/profile")  //MEMBER 용 Authorization 테스트
    public ResponseEntity getProfile() {
        return new ResponseEntity<>("MEMBER is allowed here", HttpStatus.OK);
    }
}

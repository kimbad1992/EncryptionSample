package com.encryption.encryption.controller;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.configuration2.JSONConfiguration;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


@RestController
@Slf4j
public class EncryptionController {

    private static final long EXPIRED_TIME = 1000 * 60 * 60;
    private static final String TOKEN_SECRET_KEY = "32바이트이상의긴~~~~~~~~~~~비밀키"; // JWT 검증에 사용할 시크릿 키
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding"; // 블록 암호화 방식 선택

    @GetMapping("/getToken")
    public String generateToken() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("custId", "12345678");

        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject("Subject")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRED_TIME))
                .signWith(SignatureAlgorithm.HS256, TOKEN_SECRET_KEY.getBytes())
                .compact();

        return token;
    }

    @GetMapping("/aesEncrypt")
    public String aesEncrypt(@RequestParam String jwt, HttpSession session) throws Exception {
        String randomString = getRandomData();

        Claims claims = Jwts.parser()
                .setSigningKey(TOKEN_SECRET_KEY.getBytes())
                .parseClaimsJws(jwt)
                .getBody();

        String custId = claims.get("custId", String.class);  // JWT의 클레임을 기반으로 키 생성
        byte[] salt = custId.getBytes(StandardCharsets.UTF_8);  // 클레임을 Salt로 사용

        // AES-256 단일키 생성
        SecretKey secretKey = generateAESKey(salt);

        // AES로 암호화
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(randomString.getBytes(StandardCharsets.UTF_8));
        String encryptedValue = Base64.getEncoder().encodeToString(encryptedBytes);

        return "Encrypted Value: " + encryptedValue;
    }

    @PostMapping("/rsaEncrypt")
    public String rsaEncrypt(@RequestBody Map<String, String> requestData) throws Exception {
        String publicKeyPEM = requestData.get("publicKey");

        // 헤더와 푸터 제거 및 개행 문자 제거
        publicKeyPEM = publicKeyPEM
                .replace("-----BEGIN PUBLIC KEY-----\n", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        // Base64 디코딩하여 공개 키의 바이트 배열 획득
        byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);

        // 공개 키 스펙 생성
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);

        // 공개 키 객체 생성
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey clientPublicKey = keyFactory.generatePublic(spec);

        String parsedData = getRandomData();

        // 클라이언트의 공개 키로 데이터 암호화
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
        byte[] encryptedData = cipher.doFinal(parsedData.getBytes(StandardCharsets.UTF_8));

        log.info("Encrypted Data : {}", Base64.getEncoder().encodeToString(encryptedData));

        return Base64.getEncoder().encodeToString(encryptedData);
    }



    private SecretKey generateAESKey(byte[] salt) throws Exception {
        // AES 키 생성 (256비트)
        KeySpec spec = new PBEKeySpec("password".toCharArray(), salt, 65536, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] secretKeyBytes = factory.generateSecret(spec).getEncoded();
        String secretKeyBase64 = Base64.getEncoder().encodeToString(secretKeyBytes);
        SecretKey key = new SecretKeySpec(secretKeyBytes, AES_ALGORITHM);
        log.info("AES Key : {}", secretKeyBase64);
        return key;
    }

    private String getRandomData() throws Exception{
        RestTemplate restTemplate = new RestTemplate();
        String randomData = restTemplate.getForObject("https://randomuser.me/api/", String.class);

        if (StringUtils.isEmpty(randomData)) return "error";

        JSONConfiguration config = new JSONConfiguration();
        config.read(new StringReader(randomData));
        return config.getString("results.email");
    }


}

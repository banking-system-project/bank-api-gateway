package com.bank.gateway.config;

import com.bank.gateway.util.Constants;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;

@Component
public class JwtService{


    private SecretKey getSignKey(){
        byte[] keyBytes = Decoders.BASE64.decode(Constants.SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }


    public void verifyToken(final String token){
        Jwts.parser().verifyWith(getSignKey()).build().parseSignedClaims(token);
    }



}

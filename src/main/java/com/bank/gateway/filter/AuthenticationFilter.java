package com.bank.gateway.filter;

import com.bank.gateway.config.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.ObjectInputFilter;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private RouteValidator routeValidator;

    @Autowired
    private JwtService jwtService;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (((exchange, chain) -> {

            if(routeValidator.isSecured.test(exchange.getRequest())){
                if(!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                    throw new RuntimeException("Missing Authorization Header");
                }
                String authheaders = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authheaders!=null && authheaders.startsWith("Bearer ")){
                    authheaders=authheaders.substring(7);

                }
                try{
                    System.out.println(authheaders);
                    jwtService.verifyToken(authheaders);

                }catch (Exception e){
                    System.out.println("unauthorized");
                    throw new RuntimeException("unauthorized access");
                }
            }

            return chain.filter(exchange);
        }));
    }

    public static class Config{

    }
}

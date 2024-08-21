package com.boboboom.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import com.boboboom.common.core.constant.CacheConstants;
import com.boboboom.common.core.constant.HttpStatus;
import com.boboboom.common.core.constant.SecurityConstants;
import com.boboboom.common.core.constant.TokenConstants;
import com.boboboom.common.core.utils.JwtUtils;
import com.boboboom.common.core.utils.ServletUtils;
import com.boboboom.common.core.utils.StringUtils;
import com.boboboom.common.redis.service.RedisService;
import com.boboboom.gateway.config.properties.IgnoreWhiteProperties;
import io.jsonwebtoken.Claims;
import reactor.core.publisher.Mono;

/**
 * 网关鉴权
 *
 * @author boboboom
 */
@Component
public class AuthFilter implements GlobalFilter, Ordered
{
    private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);

    // 排除过滤的 uri 地址，nacos自行添加
    @Autowired
    private IgnoreWhiteProperties ignoreWhite;

    @Autowired
    private RedisService redisService;


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain)
    {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpRequest.Builder mutate = request.mutate();

        String url = request.getURI().getPath();
        // 跳过不需要验证的路径
        if (StringUtils.matches(url, ignoreWhite.getWhites()))
        {
            return chain.filter(exchange);
        }
        String token = getToken(request);
//        log.info(exchange.getRequest().getPath()+"请求前端传过来的token:"+token);
        if (StringUtils.isEmpty(token))
        {
            return unauthorizedResponse(exchange, "令牌不能为空");
        }
        Claims claims = null;
        try {
            claims = JwtUtils.parseToken(token);
        }catch (Exception e){
            log.error("格式错误的token:"+token);
            return unauthorizedResponse(exchange, "令牌格式不正确，无法解析！");
        }
        if (claims == null)
        {
            return unauthorizedResponse(exchange, "令牌已过期或验证不正确！");
        }
        String userkey = JwtUtils.getUserKey(claims);
        boolean islogin = redisService.hasKey(getTokenKey(userkey));
        if (!islogin)
        {
            return unauthorizedResponse(exchange, "登录状态已过期");
        }
        String userid = JwtUtils.getUserId(claims);
        String username = JwtUtils.getUserName(claims);
        if (StringUtils.isEmpty(userid) || StringUtils.isEmpty(username))
        {
            return unauthorizedResponse(exchange, "令牌验证失败");
        }

        // 设置用户信息到请求
        addHeader(mutate, SecurityConstants.USER_KEY, userkey);
        addHeader(mutate, SecurityConstants.DETAILS_USER_ID, userid);
        addHeader(mutate, SecurityConstants.DETAILS_USERNAME, username);
        // 内部请求来源参数清除
        removeHeader(mutate, SecurityConstants.FROM_SOURCE);
        return chain.filter(exchange.mutate().request(mutate.build()).build());
    }

    private void addHeader(ServerHttpRequest.Builder mutate, String name, Object value)
    {
        if (value == null)
        {
            return;
        }
        String valueStr = value.toString();
        String valueEncode = ServletUtils.urlEncode(valueStr);
        mutate.header(name, valueEncode);
    }

    private void removeHeader(ServerHttpRequest.Builder mutate, String name)
    {
        mutate.headers(httpHeaders -> httpHeaders.remove(name)).build();
    }

    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange, String msg)
    {
        log.error("[鉴权异常处理]请求路径:{},异常信息:{}", exchange.getRequest().getPath(),msg);
        return ServletUtils.webFluxResponseWriter(exchange.getResponse(), msg, HttpStatus.UNAUTHORIZED);
    }

    /**
     * 获取缓存key
     */
    private String getTokenKey(String token)
    {
        return CacheConstants.LOGIN_TOKEN_KEY + token;
    }

    /**
     * 获取请求token
     */
    private String getToken(ServerHttpRequest request)
    {
        String token = request.getHeaders().getFirst(TokenConstants.AUTHENTICATION);
        // 如果前端设置了令牌前缀，则裁剪掉前缀
        if (StringUtils.isNotEmpty(token) && token.startsWith(TokenConstants.PREFIX))
        {
            token = token.replaceFirst(TokenConstants.PREFIX, StringUtils.EMPTY);
        }
        return token;
    }

    @Override
    public int getOrder()
    {
        return -200;
    }
}

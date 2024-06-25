package com.boboboom.common.security.handler;

import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.validation.BindException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import com.boboboom.common.core.constant.HttpStatus;
import com.boboboom.common.core.exception.DemoModeException;
import com.boboboom.common.core.exception.InnerAuthException;
import com.boboboom.common.core.exception.ServiceException;
import com.boboboom.common.core.exception.auth.NotPermissionException;
import com.boboboom.common.core.exception.auth.NotRoleException;
import com.boboboom.common.core.utils.StringUtils;
import com.boboboom.common.core.web.domain.AjaxResult;

/**
 * 全局异常处理器
 *
 * @author boboboom
 */
@RestControllerAdvice
public class GlobalExceptionHandler
{
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * 权限码异常
     */
    @ExceptionHandler(NotPermissionException.class)
    public AjaxResult handleNotPermissionException(NotPermissionException e, HttpServletRequest request)
    {
        String requestURI = request.getRequestURI();
        log.error("请求地址'{}',权限码校验失败'{}'", requestURI, e.getMessage());
        return AjaxResult.error(HttpStatus.FORBIDDEN, "没有访问权限，请联系管理员授权");
    }

    /**
     * 角色权限异常
     */
    @ExceptionHandler(NotRoleException.class)
    public AjaxResult handleNotRoleException(NotRoleException e, HttpServletRequest request)
    {
        String requestURI = request.getRequestURI();
        log.error("请求地址'{}',角色权限校验失败'{}'", requestURI, e.getMessage());
        return AjaxResult.error(HttpStatus.FORBIDDEN, "没有访问权限，请联系管理员授权");
    }

    /**
     * 请求方式不支持
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public AjaxResult handleHttpRequestMethodNotSupported(HttpRequestMethodNotSupportedException e,
            HttpServletRequest request)
    {
        String requestURI = request.getRequestURI();
        log.error("请求地址'{}',不支持'{}'请求", requestURI, e.getMethod());
        return AjaxResult.error(HttpStatus.BAD_METHOD,"请求方式不支持，请联系管理员。");
    }

    /**
     * 业务异常
     */
    @ExceptionHandler(ServiceException.class)
    public AjaxResult handleServiceException(ServiceException e, HttpServletRequest request)
    {
        String requestURI = request.getRequestURI();
        log.error("请求地址'{}',发生未知异常.", requestURI, e);
        Integer code = e.getCode();
        return StringUtils.isNotNull(code) ? AjaxResult.error(code, e.getMessage()) : AjaxResult.error(HttpStatus.ERROR,e.getMessage());
    }

    /**
     * 拦截未知的运行时异常
     */
    @ExceptionHandler(RuntimeException.class)
    public AjaxResult handleRuntimeException(RuntimeException e, HttpServletRequest request)
    {
        String requestURI = request.getRequestURI();
        log.error("请求地址'{}',发生未知异常.", requestURI, e);
        String message = e.getMessage();
        if(StringUtils.isNotBlank(message) && StringUtils.isChinese(message.substring(0,1))){
            return AjaxResult.error(HttpStatus.ERROR, message);
        }
        return AjaxResult.error(HttpStatus.ERROR,"系统异常，请联系管理员。");
    }

    /**
     * 系统异常
     */
    @ExceptionHandler(Exception.class)
    public AjaxResult handleException(Exception e, HttpServletRequest request)
    {
        String requestURI = request.getRequestURI();
        log.error("请求地址'{}',发生系统异常.", requestURI, e);
        String message = e.getMessage();
        if(StringUtils.isNotBlank(message) && StringUtils.isChinese(message.substring(0,1))){
            return AjaxResult.error(HttpStatus.ERROR,message);
        }
        return AjaxResult.error(HttpStatus.ERROR,"系统异常，请联系管理员。");
    }

    /**
     * 自定义验证异常
     */
    @ExceptionHandler(BindException.class)
    public AjaxResult handleBindException(BindException e)
    {
        log.error("参数绑定异常", e);
        String message = e.getAllErrors().get(0).getDefaultMessage();
        if(StringUtils.isNotBlank(message) && StringUtils.isChinese(message.substring(0,1))){
            return AjaxResult.error(HttpStatus.ERROR,message);
        }
        return AjaxResult.error(HttpStatus.ERROR,"系统异常，请联系管理员。");
    }

    /**
     * 自定义验证异常
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Object handleMethodArgumentNotValidException(MethodArgumentNotValidException e)
    {
        log.error(e.getMessage(), e);
        String message = e.getBindingResult().getFieldError().getDefaultMessage();
        if(StringUtils.isNotBlank(message) && StringUtils.isChinese(message.substring(0,1))){
            return AjaxResult.error(HttpStatus.ERROR,message);
        }
        return AjaxResult.error(HttpStatus.ERROR,"系统异常，请联系管理员。");
    }

    /**
     * 内部认证异常
     */
    @ExceptionHandler(InnerAuthException.class)
    public AjaxResult handleInnerAuthException(InnerAuthException e)
    {
        return AjaxResult.error(HttpStatus.ERROR,e.getMessage());
    }

    /**
     * 演示模式异常
     */
    @ExceptionHandler(DemoModeException.class)
    public AjaxResult handleDemoModeException(DemoModeException e)
    {
        return AjaxResult.error(HttpStatus.ERROR,"演示模式，不允许操作");
    }


}

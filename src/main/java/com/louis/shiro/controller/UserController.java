package com.louis.shiro.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @赖小燚
 * @www.louis_lai.com
 */
@Controller
@RequestMapping("/shiro")
public class UserController {

    /***
     *用户登录
     * @return
     * @author zhangenguang
     * @date 2021/9/19 17:13
     */
    @RequestMapping("/login")
    public String login(@RequestParam("username")String username,@RequestParam("password")String password){
        System.out.println("开始登录");
        Subject currentUser = SecurityUtils.getSubject();
        //用户未验证即未登录
        if(!currentUser.isAuthenticated()){
            UsernamePasswordToken token = new UsernamePasswordToken(username,password);
            token.setRememberMe(true);
            try{
                //登录
                currentUser.login(token);   //token实际上传递到自定义realm中的do方法中做参数了
            }catch (AuthenticationException ae){
                System.out.println("登录失败"+ae.getMessage());
            }
        }
        return "redirect:/pages/user/success.jsp";
    }
}

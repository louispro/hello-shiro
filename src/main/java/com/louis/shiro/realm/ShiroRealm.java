package com.louis.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.util.ByteSource;

/**
 * @赖小燚
 * @www.louis_lai.com
 */
public class ShiroRealm extends AuthenticatingRealm {
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(
            AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println("first realm");
        //1.将AuthenticationToken转换为usernamePasswordToken
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        //2.从UsernamePasswordToken中获取username
        String username = token.getUsername();
        //3.调用数据库方法，从数据库中查询username队以哦那个的用户记录
        System.out.println("从数据库中获取username："+username+"对应的信息");
        //4.若用户不存在 则抛出UnknownAccountException异常
        if("unknown".equals(username)){
            throw new UnknownAccountException("用户不存在");
        }
        //5.根据用户信息的情况，决定是否抛出其他的AuthenticationException异常
        if("monster".equals(username)){
            throw new LockedAccountException("用户被锁定");
        }
        //6.根据用户情况，构建AuthenticationInfo对象并返回，通常使用的实现类未SimpleAuthenticationInfo
        //以下信息是从数据库中获取的
        //principal:认证的实体信息，可以是username，也可以是数据表对应的用户的实体类对象
        Object principal  = username;
        //credentials:密码
        Object credentials = null;
        if("user".equals(username)){
            credentials = "098d2c478e9c11555ce2823231e02ec1";
        }
        if("admin".equals(username)){
            credentials = "038bdaf98f2037b31f1e75b5b4c9b26e";
        }
        //realmName:当前realm对象的name，调用父类的getName()方法即可
        String realmName = getName();
        //盐值
        ByteSource credentialsSalt = ByteSource.Util.bytes(username);
        SimpleAuthenticationInfo info =  new SimpleAuthenticationInfo(principal,credentials,credentialsSalt,realmName);
        return info;
    }

    public static void main(String[] args) {
        String hashAlgorithmName = "MD5";
        Object credentials = "123456";
        Object salt = ByteSource.Util.bytes("admin");
        int hashIterations = 1024;
        Object result = new SimpleHash(hashAlgorithmName,credentials,salt,hashIterations);
        System.out.println(result);
    }
}

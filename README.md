<div align="center">
	<h1>
        Shiro学习笔记
    </h1>    
</div>
## 目录

#### <a href="one">一、快速入门</a>

#### <a href="#two">二、集成Spring</a>

#### <a href="#three">三、Shiro入门到入土</a>

<hr/>

<h2 id="one">一、快速入门</h2>

#### 1.1、导入依赖

```xml
<!--shiro依赖-->
<dependency>
  <groupId>org.apache.shiro</groupId>
  <artifactId>shiro-all</artifactId>
  <version>1.7.1</version>
</dependency>
<!--日志依赖-->
<dependency>
  <groupId>org.slf4j</groupId>
  <artifactId>slf4j-log4j12</artifactId>
  <version>1.7.32</version>
</dependency>
```

#### 1.2、快速入门

```java
package com.louis.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Simple Quickstart application showing how to use Shiro's API.
 *
 * @since 0.9 RC2
 */
public class Quickstart {

    private static final transient Logger log = LoggerFactory.getLogger(Quickstart.class);


    public static void main(String[] args) {

        // The easiest way to create a Shiro SecurityManager with configured
        // realms, users, roles and permissions is to use the simple INI config.
        // We'll do that by using a factory that can ingest a .ini file and
        // return a SecurityManager instance:

        // Use the shiro.ini file at the root of the classpath
        // (file: and url: prefixes load from files and urls respectively):
//        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
//        SecurityManager securityManager = factory.getInstance();
        //获取权限管理器并且设置域
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        IniRealm realm = new IniRealm("classpath:shiro.ini");
        defaultSecurityManager.setRealm(realm);
        // for this simple example quickstart, make the SecurityManager
        // accessible as a JVM singleton.  Most applications wouldn't do this
        // and instead rely on their container configuration or web.xml for
        // webapps.  That is outside the scope of this simple quickstart, so
        // we'll just do the bare minimum so you can continue to get a feel
        // for things.
        SecurityUtils.setSecurityManager(defaultSecurityManager);

        // Now that a simple Shiro environment is set up, let's see what you can do:

        // get the currently executing user:
        // 获取当前的 Subject. 调用 SecurityUtils.getSubject();
        Subject currentUser = SecurityUtils.getSubject();

        // Do some stuff with a Session (no need for a web or EJB container!!!)
        // 测试使用 Session
        // 获取 Session: Subject#getSession()
        Session session = currentUser.getSession();
        session.setAttribute("someKey", "aValue");
        String value = (String) session.getAttribute("someKey");
        if (value.equals("aValue")) {
            log.info("---> Retrieved the correct value! [" + value + "]");
        }

        // let's login the current user so we can check against roles and permissions:
        // 测试当前的用户是否已经被认证. 即是否已经登录.
        // 调动 Subject 的 isAuthenticated()
        if (!currentUser.isAuthenticated()) {
           // 把用户名和密码封装为 UsernamePasswordToken 对象
            UsernamePasswordToken token = new UsernamePasswordToken("lonestarr", "vespa");
            // rememberme
            token.setRememberMe(true);
            try {
               // 执行登录.
                currentUser.login(token);
            }
            // 若没有指定的账户, 则 shiro 将会抛出 UnknownAccountException 异常.
            catch (UnknownAccountException uae) {
                log.info("----> There is no user with username of " + token.getPrincipal());
                return;
            }
            // 若账户存在, 但密码不匹配, 则 shiro 会抛出 IncorrectCredentialsException 异常。
            catch (IncorrectCredentialsException ice) {
                log.info("----> Password for account " + token.getPrincipal() + " was incorrect!");
                return;
            }
            // 用户被锁定的异常 LockedAccountException
            catch (LockedAccountException lae) {
                log.info("The account for username " + token.getPrincipal() + " is locked.  " +
                        "Please contact your administrator to unlock it.");
            }
            // ... catch more exceptions here (maybe custom ones specific to your application?
            // 所有认证时异常的父类.
            catch (AuthenticationException ae) {
                //unexpected condition?  error?
            }
        }

        //say who they are:
        //print their identifying principal (in this case, a username):
        log.info("----> User [" + currentUser.getPrincipal() + "] logged in successfully.");

        //test a role:
        // 测试是否有某一个角色. 调用 Subject 的 hasRole 方法.
        if (currentUser.hasRole("schwartz")) {
            log.info("----> May the Schwartz be with you!");
        } else {
            log.info("----> Hello, mere mortal.");
            return;
        }

        //test a typed permission (not instance-level)
        // 测试用户是否具备某一个行为. 调用 Subject 的 isPermitted() 方法。
        if (currentUser.isPermitted("lightsaber:weild")) {
            log.info("----> You may use a lightsaber ring.  Use it wisely.");
        } else {
            log.info("Sorry, lightsaber rings are for schwartz masters only.");
        }

        //a (very powerful) Instance Level permission:
        // 测试用户是否具备某一个行为.
        if (currentUser.isPermitted("user:delete:zhangsan")) {
            log.info("----> You are permitted to 'drive' the winnebago with license plate (id) 'eagle5'.  " +
                    "Here are the keys - have fun!");
        } else {
            log.info("Sorry, you aren't allowed to drive the 'eagle5' winnebago!");
        }

        //all done - log out!
        // 执行登出. 调用 Subject 的 Logout() 方法.
        System.out.println("---->" + currentUser.isAuthenticated());

        currentUser.logout();

        System.out.println("---->" + currentUser.isAuthenticated());

        System.exit(0);
    }
}
```

<h2 id="two">二、集成Spring</h2>

#### 2.1、`web.xml`中配置`shiro`

```xml
<!--配置shiro-->
<filter>
  <filter-name>shiroFilter</filter-name>
  <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
  <init-param>
    <param-name>targetFilterLifecycle</param-name>
    <param-value>true</param-value>
  </init-param>
</filter>
<filter-mapping>
  <filter-name>shiroFilter</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
```

#### 2.2、在`spring.xml`中配置`shiro`

```xml
<!--配置CacheManager缓存管理器-->
<!--需要导入缓存依赖和缓存配置文件-->
<bean id="cacheManager" class="org.apache.shiro.cache.ehcache.EhCacheManager">
    <property name="cacheManagerConfigFile" value="classpath:ehcache.xml"></property>
</bean>

<!--配置realm,直接配置实现了realm接口的bean-->
<bean id="jdbcRealm" class="com.louis.shiro.realm.ShiroRealm">
</bean>

<!--配置SecuritManager-->
<bean id="securityManager" class="org.apache.shiro.web.mgt.DefaultWebSecurityManager">
    <property name="cacheManager" ref="cacheManager"></property>
    <property name="realm" ref="jdbcRealm"></property>
</bean>

<!--spring和 shiro集成-->
<!--配置LifecycleBeanPostProcessor，可以自定义的来调用配置在spring ioc容器中的shiro bean 的生命周期 方法-->
<bean id="lifecycleBeanPostProcessor" class="org.apache.shiro.spring.LifecycleBeanPostProcessor"></bean>

<!--启用ioc容器的组件使用shiro的注解，但必须在配置了LifeCycleBeanPostProcessor之后才可以用-->
<bean class="org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator"
      depends-on="lifecycleBeanPostProcessor"/>
<bean class="org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor">
    <property name="securityManager" ref="securityManager"></property>
</bean>

<!--配置shiroFilter-->
<!--id必须和web.xml文件中配置的shiroFilter的filter-name一样-->
<bean id="shiroFilter" class="org.apache.shiro.spring.web.ShiroFilterFactoryBean">
    <property name="securityManager" ref="securityManager"></property>
    <!--登录界面-->
    <property name="loginUrl" value="/pages/user/login.jsp"></property>
    <!--登录成功界面-->
    <property name="successUrl" value="/pages/user/list.jsp"></property>
    <!--未通过权限检验页面-->
    <property name="unauthorizedUrl" value="/pages/user/unauthorized.jsp"></property>
    <!--配置哪些页面需要保护，以及访问这些 页面需要的权限-->
    <property name="filterChainDefinitions">
        <value>
            <!--anno表示可以匿名访问-->
            /pages/user/login.jsp = anon
            <!--authc表示必须认证之后才能访问-->
            /** = authc
        </value>
    </property>
</bean>
```

<h2 id="three">三、Shiro入门到入土</h2>

#### 3.1、工作流程

<img src="http://tva1.sinaimg.cn/large/006gOimwgy1gulztzzmqzj60o50epjul02.jpg"/>

工作流程：由于在`web.xml`配置的是`/*`，所以所有的请求都会经过`shiroFilter`,未经认证的请求会重定向至`loginUrl`,经过认证的或允许匿名访问的会放行。

#### 3.2、`DelegatingFilterProxy`

`DelegatingFilterProxy`实际上是Filter的一个代理对象，默认情况下，`Spring`会到`IOC`容器中查找和`<filter-name>`对应的`filter bean`,也可以通过`targetBeanName`的初始化参数来配置`filter bean`的`id`

#### 3.3、URL匹配模式

- `url`模式使用`Ant`风格模式
- `Ant`路径通配符支持`？`，`*`，`**`,注意通配符匹配不包括 目录分隔符 /
  - `?`：匹配一个字符
  - `*`：匹配零个或多个字符
  - `**`：匹配路径中的零个或多个路径

`shiro`中`url`匹配格式为 ：`url=拦截器[参数]`

1. ##### url匹配顺序

   <div align="center">

   <img src="http://tva1.sinaimg.cn/large/006gOimwgy1gum0url6m2j60p80ehtfz02.jpg"/>

   </div>

#### 3.4、认证流程

1. 获取当前的`Subject`，调用`SecurityUtils.getSubject();`

2. 测试当前用户是否已经被认证。即是否已经登录，调用`Subject`的`isAuthenticated();`

3. 若没有被认证，则把用户名和密码封装为`UsernamePasswordToken`对象

   - 创建一个表单页面
   - 把请求提交到`SpringMVC的Handler`
   - 获取用户名和密码

4. 执行登录：调用`Subject`的`login(AuthenticationToken)`方法

5. 自定义Realm的方法，从数据库中获取对应的记录，返回给`shiro`

   自定义Realm需要继承`AuthenticatingRealm`类，实现`doGetAuthenticationInfo(AuthenticationToken)`方法

6. 有`shiro`完成密码的对比

**认证实现**

```java
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
```

**实现realm进行验证：**

```java
package com.louis.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.Realm;

/**
 * @赖小燚
 * @www.louis_lai.com
 */
public class ShiroRealm extends AuthenticatingRealm {
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(
            AuthenticationToken authenticationToken) throws AuthenticationException {
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
        Object credentials = "123456";
        //realmName:当前realm对象的name，调用父类的getName()方法即可
        String realmName = getName();
        SimpleAuthenticationInfo info =  new SimpleAuthenticationInfo(principal,credentials,realmName);
        return info;
    }
}
```

#### 3.5、密码对比

密码对比通过`AuthenticationRealm`的`credentialsMatcher`属性进行的密码的比对，底层实际上还是调用`equals()`方法

1. 使用`MD5`算法加密

   在自定义`realm`配置加密算法：

   ```xml
   <!--配置realm,直接配置实现了AuthenticationRealm接口的bean-->
   <bean id="jdbcRealm" class="com.louis.shiro.realm.ShiroRealm">
       <!--用MD5算法对前台输入的密码进行加密-->
       <property name="credentialsMatcher">
           <bean class="org.apache.shiro.authc.credential.HashedCredentialsMatcher">
               <!--加密算法-->
               <property name="hashAlgorithmName" value="MD5"></property>
               <!--加密次数-->
               <property name="hashIterations" value="1024"></property>
           </bean>
       </property>
   </bean>
   ```

   其底层是调用`new SimpleHash(hashAlgorithmName,credentials,salt,hashIterations)`进行加密的

   但这个算法存在问题：

   ​	当两个用户的密码的一样时，`MD5`算法加密获得的密码是一样的，所以需要在`MD5`算法中加盐值。

   `MD5`盐值加密：

   1. 在`doGetAuthenticationInfo()`方法返回值创建`SimpleAuthenticationInfo`对象的时候，需要使用`SimpleAuthenticationInfo(principal,credentials,credentialsSalt,realmName)`构造器
   2. 使用`ByteSource.Util.bytes()`计算盐值
   3. 盐值需要唯一：一般 使用随机字符或`user id`
   4. 使用`new SimpleHash(hashAlgorithmName,credentials,salt,hashIterations)`计算盐值加密后的密码的值

#### 3.6、多Realm验证

多realm验证实现：

```java
protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
    this.assertRealmsConfigured();
    Collection<Realm> realms = this.getRealms();
    return realms.size() == 1 ? this.doSingleRealmAuthentication((Realm)realms.iterator().next(), authenticationToken) : this.doMultiRealmAuthentication(realms, authenticationToken);
}
```

多realm配置：

```xml
<!--配置CacheManager缓存管理器-->
<!--需要导入缓存依赖和缓存配置文件-->
<bean id="cacheManager" class="org.apache.shiro.cache.ehcache.EhCacheManager">
    <property name="cacheManagerConfigFile" value="classpath:ehcache.xml"></property>
</bean>

<!--配置realm,直接配置实现了realm接口的bean-->
<bean id="jdbcRealm" class="com.louis.shiro.realm.ShiroRealm">
    <!--用MD5算法对前台输入的密码进行加密-->
    <property name="credentialsMatcher">
        <bean class="org.apache.shiro.authc.credential.HashedCredentialsMatcher">
            <!--加密算法-->
            <property name="hashAlgorithmName" value="MD5"></property>
            <!--加密次数-->
            <property name="hashIterations" value="1024"></property>
        </bean>
    </property>
</bean>

<!--第二个自定义realm-->
<bean id="secondRealm" class="com.louis.shiro.realm.SecondRealm">
    <property name="credentialsMatcher">
        <bean class="org.apache.shiro.authc.credential.HashedCredentialsMatcher">
            <property name="hashIterations" value="1024"></property>
            <property name="hashAlgorithmName" value="SHA1"></property>
        </bean>
    </property>
</bean>

<bean id="authenticator" class="org.apache.shiro.authc.pam.ModularRealmAuthenticator">
    <!--多realms认证策略，默认为AtLeastOneSuccessfulStrategy-->
    <property name="authenticationStrategy">
        <bean class="org.apache.shiro.authc.pam.AllSuccessfulStrategy"></bean>
    </property>
    <property name="realms">
        <list>
            <ref bean="jdbcRealm"/>
            <ref bean="secondRealm"/>
        </list>
    </property>
</bean>

<!--配置SecuritManager-->
<bean id="securityManager" class="org.apache.shiro.web.mgt.DefaultWebSecurityManager">
    <property name="cacheManager" ref="cacheManager"></property>
    <property name="authenticator" ref="authenticator"></property>
</bean>
```

多realm认证策略：

`FirstSuccessfulStrategy`只要有一个realm验证成功即可，且只返回第一个realm身份验证成功的认证信息，其他的忽略

`AtLeastOneSuccessfulStrategy`只要有一个realm验证成功即可，但其会将所有realm的验证信息返回

`AllSuccessfulStrategy`所有realm验证成功才算成功且返回所有realm身份验证成功的认证信息，如果有一个失败就验证失败

3.7、授权



<h2 id="problem">学习中遇到的问题</h2>

1. ` The security manager does not implement the WebSecurityManager interface.`

   原理：ioc容器中的`class`为`DefaultSecurityManager`

   ```xml
   <bean id="securityManager" class="org.apache.shiro.mgt.DefaultSecurityManager">
       <property name="cacheManager" ref="cacheManager"></property>
       <property name="realm" ref="jdbcRealm"></property>
   </bean>
   ```

   解决办法：将`DefaultSecurityManager`改为`DefaultWebSecurityManager`

2. `echacheManager`无法初始化

   ```xml
   <!--配置CacheManager缓存管理器-->
   <!--需要导入缓存依赖和缓存配置文件-->
   <bean id="cacheManager" class="org.apache.shiro.cache.ehcache.EhCacheManager">
       <property name="cacheManagerConfigFile" value="classpath:ehcache.xml"></property>
   </bean>
   ```

   原因：`echache.xm`l配置文件信息出错

   解决办法：自己重新配置

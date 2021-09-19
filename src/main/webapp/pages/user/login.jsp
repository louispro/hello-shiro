<%--
  Created by IntelliJ IDEA.
  User: louis_lai
  Date: 2021/9/19
  Time: 12:30
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" isELIgnored="false" pageEncoding="UTF-8" %>
<html>
<head>
    <title>登录</title>
    <base href="http://localhost:8080/shiro/">
    <form action="shiro/login" method="post">
        姓名：<input type="text" value="louis" name="username"/><br/>
        密码：<input type="text" name="password" value="123456"/><br/>
        <input type="submit" value="登录"/><br/>
    </form>
</head>
<body>
    <h4>登录</h4>
</body>
</html>

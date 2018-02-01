# AutoRepeater: Automated HTTP Request Repeating With Burp Suite

## tl;dr
Within extender import AutoRepeater.jar

## Some Brief Instructions
AutoRepeater will only resend requests which are changed by a defined replacement. When AutoRepeater receives a request that matches the conditions set for a given tab, AutoRepeater will first apply every defined base replacement to the request, then will copy the request with the base replacements performed for each defined replacement and apply the given replacement to the request. 

## Introduction
Burp Suite is an intercepting HTTP Proxy, and it is the defacto tool for performing web application security testing. While Burp Suite is a very useful tool, using it to perform authorization testing is often a tedious effort involving a "change request and resend" loop, which can miss vulnerabilities and slow down testing. AutoRepeater, an open source Burp Suite extension, was developed to alleviate this effort. AutoRepeater automates and streamlines web application authorization testing, and provides security researchers with an easy-to-use tool for automatically duplicating, modifying, and resending requests within Burp Suite while quickly evaluating the differences in responses.

![AutoRepeater](./ar.png)

## AutoRepeater
Without AutoRepeater, the basic Burp Suite web application testing flow is as follows:

1. User noodles around a web application until they find an interesting request 
2. User sends the request to Burp Suite's "Repeater" tool
3. User modifies the request within "Repeater" and resends it to the server
4. Repeat step 3 until a sweet vulnerability is found
5. Start again from step 1, until the user runs out of testing time or can retire from bug bounty earnings

While this testing flow works, it is particularly tedious for testing issues that could exist within any request. For example, changing email addresses, account identities, roles, URLs, and CSRF tokens can all lead to vulnerabilities. Currently, Burp Suite does not quickly test for these types of vulnerabilities within a web application.

There are some existing Burp Suite plugins (AuthMatrix, Authz, and Autorize) which exist to make authorization testing easier but each has issues that limit their usefulness. AuthMatrix and Authz require users to send specific requests to the plugins and set up rules for how the authorization testing is performed, which introduces the risk of missing important requests and slows down testing. Autorize does not provide the users with the ability to perform general -purpose text replacements, can only perform one header or cookie replacement at a time, and has a confusing user interface. AutoRepeater takes all the best ideas from these plugins, along with the Burp Suite's familiar user interface, and combines them to create the most streamlined authorization testing plugin.

AutoRepeater provides a general-purpose solution for streamlining authorization testing within web applications. AutoRepeater provides the following features:

+ Automatically duplicate, modify, and resend any request
+ Conditional replacements
+ Quick header, cookie, and parameter value replacements
+ Split request/response viewer
+ Original vs. modified request/response diff viewer
+ Base replacements for values that break requests like CSRF tokens and session cookies
+ Renamable tabs
+ Logging
+ Exporting
+ Toggled activation
+ "Send to AutoRepeater" from other Burp Suite tools

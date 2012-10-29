serialization
=============

Extender module for BurpSuite to decode and re-encode JAVA Object Serialization for security testing


#  serialization.rb - User Guide

## Overview

The serialization.rb is a BurpSuite extension that allows efficient
testing of business login of Java applications utilizing serialized
communication. Installation instructions below describe the dependencies
and user guide section gives a brief glimpse to the added functionality.

## Installation

These installation instructions are for Debian but should work the same
on Ubuntu. For other distributions you will need to adapt them
appropriately.

First some dependencies must be met:  
`$ sudo apt-get install jruby`  
`$ sudo jruby -S gem install buby`  
`$ sudo jruby -S gem install rbkb`  
`$ sudo apt-get install libxstream-java`  
`$ mkdir lib`  
`$ ln -s /usr/share/java/xstream-1.3.1.jar lib/`  
`$ ln -s /opt/burp/burpsuite_pro_v1.5rc3.jar burp.jar`  

JRuby that is installed first is a Java implementation of Ruby allowing
us to write Java extensions in Ruby and access Java APIs.
First of the used gems, buby, provides access to BurpSuite extender API
and second is Ruby BlackBag, a ruby helper library  for penetration
testing and reverse engineering (hexdump is probably the only feature
currently used).

The XStream library serializes and de-serializes the data being
transmitted between client app and server. And naturally BurpSuite is
also needed.

Once everything is set up, everything should start with following
command:

`$ jruby serialization.rb`  

## User Guide

Once BurpSuite is loaded with the serialization extender module
properly, there will be some extra messages in the Alerts tab. These
inform that Jruby::Buby registered a callback and that three MenuItem
handlers are registered.

### Menus

Looking for example at the repeater menu, you can see new menu items
there provided by serialization.rb as shown on following screen capture:

![Menus](serialization/tree/master/images/menu2.png)

New items are "Reload JARs" that will load all .jar files from the lib
directory. "Drop to IRB" drops the starting shell to IRB allowing
modifications and inspection of internal objects on-the-fly. Finally the
"Reload serialization.rb" will reload the source file of
serialization.rb thus enabling us to do modifications to the actual
sources of serialization.rb and get them into use easily.

### Proxy

The basic functionality of Proxy tool is quite simple. The
serialization.rb shows an XML version of the request as shown in the
screenshot from History tab. You can intercept and modify the request
normally. The additional information in the History tab is the original
request and edited response showing the serialized format. However, this
information is not that interesting to us normally.

![Proxy](serialization/tree/master/images/history.png)

### Intruder 

Following screen shot shows the XML format of a request (as would be
also seen in Proxy tool). There is an additional header field
<b>X-Burp: Decoded</b> shown in the request that tells our serialization
module to re-serialize the data before sending it out (this header is
stripped of from the request that is actually sent out).

![Intruder](serialization/tree/master/images/intruder.png)


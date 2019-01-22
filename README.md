Transparant HTTP proxy client
---

If you require a HTTP proxy to connect to the internet, you will soon
find out that every application has it's own way to 
configure proxy settings, or worse, doesn't support proxies at all.

This application will run in the background and route all* traffic trough
the proxy without explicit support from an application.

### What you need

- MacOS 

  I have a working Linux version, but I'm to lazy to put it here.

- An HTTP proxy 

  The proxy needs to allow CONNECT to any port. You will find out if your proxy
  allows this very fast after setting it up.
 
- Some time to set it up

  It works, but it's a little finicky.

### What doesn't work

- Any traffic that is not using TCP

Nothing to be done about this, as HTTP is inherently TCP.

- Port 534

Port 534 is used by the proxy and any traffic to this port will be routed incorrectly.

Setup
---

1. **Allow traffic redirecting**

    Edit `/etc/pf.conf` using
    
    ```sh
    sudo nano /etc/pf.conf
    ```
    
    or some other editor. Then add `rdr-anchor "proxy"` and `anchor "proxy"`. These 
    have to be in the correct order. In the end the file should look like this:
    
    ```
    scrub-anchor "com.apple/*"
    nat-anchor "com.apple/*"
    rdr-anchor "com.apple/*"
    rdr-anchor "proxy"
    dummynet-anchor "com.apple/*"
    anchor "com.apple/*"
    anchor "proxy"
    load anchor "com.apple" from "/etc/pf.anchors/com.apple"
    ```

2. **Install the application**
  
    Put the application somewhere where you can remember
    
    ```
    sudo cp proxy /opt/proxy
    ```
    
3. **Launch on boot**

    Edit and copy the included service file
    
    ```
    nano net.nandoe.proxy.plist
    ```
    
    Configure PROXY_USER and PROXY_PASSWORD with the correct value.
    
    ```
    sudo cp net.nandoe.proxy.plist /Library/LaunchDaemons/
    sudo launchtl load /Library/LaunchDaemons/net.nandoe.proxy.plist
    ```
    
    
    

<h1 align="center">
    mysapsso2-sp-token-adapter
</h1>

<p align="center" style="font-size: 1.2rem;"> 
    This code provides Ping Federate SAP SSO Integration to Java and ABAP backend stacks without the need for the Netweaver Gateway to create MYSAPSSO2 cookies.  
    <br/>
    Imbedded in this repository is the <code>TicketCreator.java</code> class, which is a stand-alone java class which generates the MYSAPSSO2 cookie, and thus could be used multiple integration types.
    <br/>
    This repository gives a template for allowing SAP GUI SSO login via downloading an SAP GUI Shortcut file, but the primary use could be for enabling API calls to SAP, authenticated through Ping Federate, with SSO passthrough to the SAP backend without needing to redirect off of a SAP Netweaver Portal (Java) system.
</p>

<p align="center">

</p>

## Summary
This solution provides SAP SSO for web applications such as the SAP Portal, and SAP Fiori applications, as well as thick client SAP application such as the SAP GUI.  The solution is HTTPS throughout, so credentials are always encrypted.  MFA of course could be added via the Ping Federate authentication policy setup.

The SAP GUI portion of the solution generates a “SAPShortcut” file.  The user clicks on this file which launches the SAP GUI.  Once the user selects which system then want to log into, SSO logs them in. 

The SAP web portion of the solution accepts a redirect url, and simply generates a MYSAPSSO2 cookie before forwarding the request to the redirected application.  The benefit of this solution is that it works exactly the same way as the SAP solution, but does not require the SAP Netweaver Portal as an intermediary system. 

## Prerequisites

The public key for the signing certificate must be obtained from a Ping administrator. 

A user in the target SAP system/SID needs to log into the GUI and start transaction STRUSTSSO2. 

Click on the “Import Certificate” button located in the middle of the screen. 

PICTURES

With the certificate imported, click on the button “Add to certificate List”.  This will add a “CN=PNGFED01” entry to the window above. 

PICTURES

Click on the “Add to ACL” button and add the parameters exactly as shown in the screenshots below: 

PICTURES

Click on the “Save” icon at the top of the screen. 

You can continue to use SNC for encrypting the SAP GUI traffic with either the SAP provided SNC libraries or a third party provided SNC library.  SNC is completely independent from the SSO login capability to the SAP GUI.


# User Experience for SAP GUI

Open browser and navigate to https://<pingfederatehostname>:<port>/sp/startSSO.ping?SpSessionAuthnAdapterId=SAPGUI or deploy this a web browser shortcut to the users desktop.  Double clicking this shortcut will launch the users default web browser 

Example: 

PICTURES

Authenticate 
PICTURES 

Provide a second factor 

PICTURES

The next page displays and auto downloads a SAPGUI.sap “SAP shortcut” file.  Double clicking (opening) the file takes you to the real SAP GUI on the local PC.  Follow the instructions on the screen to launch the client. 

Here is how Chrome looks: 
PICTURES

# User experience for SAP web applications (Fiori or other SAP proprietary web application technologies like ITS)
Simply use the following URL and provide the appropriate TargetResource. 

https://<pingfederatehostname>:<port>/sp/startSSO.ping?SpSessionAuthnAdapterId=SAPGUI&TargetResource=<TargetWebURL> 

Example:  To generate a MYSAPSSO2 cookie for the web application located at http://yourapp.com, simply use this URL.  https://<pingfederatehostname>:<port>/sp/startSSO.ping?SpSessionAuthnAdapterId=SAPGUI&TargetResource=http://yourapp.com 

<!--
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017 ForgeRock AS.
 * Portions copyright 2018 David Luna.
-->
# Profile Attribute To State Node

A simple authentication node for ForgeRock's [Identity Platform][forgerock_platform] 5.5 and above. This node can be used to pull information from a (previously identified in the authentication tree) user's profile into the shared authentication state for easy reference by subsequent nodes in the tree.

As values returned from a profile's attributes are returned as Sets, this node offers various ways to select the element(s) from that Set, determined by the choice of **selection type** parameter. 

These states operate as:

* **SelectExact** The object will be copied exactly as is (as a Set) into the shared state. Be careful that other nodes using this value expect this object to be a Set when reading and using it.
* **SelectFirst** The object's first value will be copied in (as a String) into the shared state. This is the default mode, and is likely the most useful for single-item attribute values.
* **SelectAsString** The entire object will be converted to a String, and the resulting String will be placed in the shared state. This mode may be useful for multi-value attributes, but caution should be used in subsequent nodes to understand the output format.

![ScreenShot](./example.png)
Configuration Screenshot

The above screenshot demonstrates the flexibility of authentication nodes by generating a very (VERY!) simple device fingerprinting journey using granular authentication nodes. By storing the user's current browser in the authentication shared state and comparing it against the previous browser used to authenticate as stored in the user's profile we are able to increase or decrease their authentication level, before storing the new previous browser value in the profile.

Copy the .jar file from the ../target directory into the ../web-container/webapps/openam/WEB-INF/lib directory where AM is deployed.  Restart the web container to pick up the new node.  The node will then appear in the authentication trees components palette.
        
The code in this repository has binary dependencies that live in the ForgeRock maven repository. Maven can be configured to authenticate to this repository by following the following [ForgeRock Knowledge Base Article](https://backstage.forgerock.com/knowledge/kb/article/a74096897).        
        
The sample code described herein is provided on an "as is" basis, without warranty of any kind, to the fullest extent permitted by law. ForgeRock does not warrant or guarantee the individual success developers may have in implementing the sample code on their development platforms or in production configurations.

ForgeRock does not warrant, guarantee or make any representations regarding the use, results of use, accuracy, timeliness or completeness of any data or information relating to the sample code. ForgeRock disclaims all warranties, expressed or implied, and in particular, disclaims all warranties of merchantability, and warranties related to the code, or any service or software related thereto.

ForgeRock shall not be liable for any direct, indirect or consequential damages or costs of any type arising out of any action taken by you or others related to the sample code.

[forgerock_platform]: https://www.forgerock.com/platform/  

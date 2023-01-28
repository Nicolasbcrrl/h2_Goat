# h2_Goat

## Security Misconfiguration
### Overview of the study
- This category represents the fifth most common security vulnerability according to the OWASP Top 10 critical security of 2021.
- 90% of the applications were tested. From this test, 4.51% crash rate and more than 280 K CWE was found for this category.
- Among the security vulnerabilities identified by the CWE, the CWE-16 and CWE-611 categories are the most present. CWE-16 represents weaknesses introduced during the configuration of the software. CWE-611 represents weaknesses in software that processes XML documents that may contain XML entities with URIs that refer to documents outside of the control environment, which may result in corrupted output.

### Description
An application falls into this category if it meets any of the following conditions : 
- misconfiguration of permissions on cloud services and no security hardening of all protocol layers.
- activation or installation of features that are useless or will never be used. 
- temporary or default accounts are still active and have the original password.
- the user has access to a surplus of information contained in error messages and error handling.
- the latest security features are not enabled or not configured for updated systems.
- security settings and functionality of frameworks, libraries, databases, etc., are not implemented.
- Security headers or directives does send by the server.
- the software used is not up to date.

### How to Prevent
- Configure the development, quality assurance and production environments in the same way, so that there is a single hardening process applicable to all environments.
- Install only what you need to use, do not install anything superfluous.
- Set up a task in charge of reviewing and updating the configuration in accordance with all the security measures (notes, patch, fix and update). Also review cloud storage permissions.
- Use a segmented application architecture.
- Ensure security directives (security headers) are sent to clients.
- Automate the process of monitoring the operation and effectiveness of configurations and settings of environments.

### Example Attack Scenarios
#### Scenario 1
An application server is delivered with test applications. These applications have not been removed from the production server, this represents a security breach. If one of these applications is the administrator console and still has the default account, this represents an opportunity for the attacker to log in with this account using the default password and compromise the server. 
#### Scenario 2
The directory list is still active on the server. This provides an opportunity for a hacker to find it and download the java classes, which he will then decompile and reverse engineer. He will then be able to view the code and find access holes in the application.
#### Scenario 3
The server configuration allows very detailed errors to be returned to users. This potentially exposes sensitive information to the attacker.
#### Scenario 4
A cloud provider has default sharing permissions open to other cloud providers across the internet. This allows access to sensitive data stored in the cloud.

## Vulnerable and Outdated Components

### Overview of the study
- This category represents the sixth most common security vulnerability according to the OWASP Top 10 critical security of 2021.
- Catégorie qui est compliqué à tester et à évaluer le risque de cette vulnerabiliter. 
- Cette catégorie ne possède pas de Common Vulnerability and Exposures (CVE) associé aux CWEs inclu.
- Les CWEs qui sont associer à cette catégorie sont CWE-1104 et les deux CWEs du Top 10 de 2013 et 2017
- CWE-1104 représente les faiblesses lié à l'utilisation de composants tiers non maintenus.

### Description

You are exposed to vulnerabilities if you meet any of the following conditions: 
- You do not know the version of your components and nested dependencies.
- If you have an operating system, web/application server, database system or application that is outdated or no longer supported by the developer, you are vulnerable.
- Do not research information about old or new vulnerabilities.
- Do not upgrade the underlying platform, frameworks and dependencies.
- If compatibility between updated, upgraded or patched libraries is not tested by the developers.
- If no components security is done.

### How to Prevent

Afin d'éviter aux mieux les vulnérabilité, un processus de gestion des correctifs doit être mis en place pour : 
- Supprimer tout ce qui superflux et inutile (dépendances, fichiers, composants, fonctionnalités, documentations, etc.).
- Faire un inventaire des versions de vos composants aussi bien du côté client comme du côté server, ainsi que de leurs dépendances. Des outils comme OWASP Dependency Check, retire.js, etc. vous permette de faire votre inventaire. De plus, surveiller constament les nouvelles vulnérabilité dans les composant, à l'aide de site internet comme Common Vulnerability and Exposures (CVE) et National Vulnerability Database (NVD). 
- Aquirez vos composant seulement chez des fournisseurs officiel.
- Tenez vous informers sur les bibliothèques et les composant qui ne sont plus supporter ou qui ne publie plus de correctif. 

### Exemples Attack Scenarios

Components run with the same level of privileges as the application that uses them. This implies that a vulnerability on any of these components can have serious consequences.

- The CVE-2017-5638 vulnerability allows remote code execution of the Struts 2 framework, which allows the execution of arbitrary code on the server.
- Vulnerabilities are very present on IoTs and are generally difficult or impossible to patch.
- The Shodan IoT search engine is one of the tools that help attackers find vulnerable systems. It can help the attacker to find systems with the Heartbleed vulnerability patched in April 2014. The Heartbleed vulnerability is a weakness that allows the theft of information protected by the SSL/TLS encryption used for internet security. 


"The Heartbleed bug allows anyone on the Internet to read the memory of the systems protected by the vulnerable versions of the OpenSSL software." (source : heartbleed.com)



# h2_Goat

## Security Misconfiguration
### Overview of the study
- This category represents the fifth most responded security vulnerability according to the OWASP Top 10 critical security of 2021.
- 90% of the applications were tested. From this test, 4.51% crash rate and more than 280 K CWE was found for this category.
- Among the security vulnerabilities identified by the CWE, the CWE-16 and CWE-611 categories are the most present. CWE-16 represents weaknesses introduced during the configuration of the software. CWE-611 represents weaknesses in software that processes XML documents that may contain XML entities with URIs that refer to documents outside of the control environment, which may result in corrupted output.

### Description
An application falls into this category if it meets any of the following conditions 
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
Un serveur d'application est livré avec des application de test. Ces applications n'ont pas été retirer du server de production, cela représente une faille de sécurité. Dans le cas que l'un de ces application soit la console administrateur et suposon encore qu'elle possède toujours le compte par défault, cela représente une oportunité pour l'attaquant de se connecter avec ce compte en utilisant le mots de passe par défault et ainsi compromettre le server. 
#### Scenario 2
La liste des répertoir est toujours active sur le serveur. Cela offre la possibilité à un hacker de la trouvé et de téléchargé les classe java, qu'il va ensuite décompiler et faire de l'ingénieurie inverse. Il sera alors en mesure de visualiser le code et trouvé des faille d'accès dans l'application.
#### Scenario 3
La configuration du serveur permet de renvoyer des erreurs très détailler aux utilisateurs. Cela expose potentiellement des informations sensibles à l'attaquant.
#### Scenario 4
Un fournisseur cloud possède des autorisation de partage par défaut ouverte a d'autre fournisseur cloud à travers internet. Ce qui permet un accès au données sensible stockée dans le cloud.

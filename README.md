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

## Injection

### Overview of the study
- This category represents the sixth most common security vulnerability according to the OWASP Top 10 critical security of 2021.
- 94% of the applications were tested. Ce teste a révélé un taux maximal de 19% d'incident, pour une moyen de 3% d'incident et plus de 274k d'occurence CWE.
- Parmis les 274k CWE occurences, la CWE-79, la CWE-89 et la CWE-73 sont les catégories les plus présente. 
- CWE-79 : Cross-site scripting, est un type de faille de sécurité des site internet qui pemet l'injection de contenu dans une page internet. Cela proque ainsi des actions sur les navigateur web visitant la page.
- CWE-89 : injection SQL, est un type de faille de sécurité qui permet à l'attaquant de rentrer des commandes sql, dans le but de volé, modifier ou détruire des données.
- CWE-73 : External Control of File Name or Path, est un type de faille de sécurtite de logiciel qui permet à un utilisateur d'entrer et de contôler ou influencer les chemins ou les noms de fichiers dans les opérations du système de fichiers.

### Description
- Data entered by users is not validated, checked or filtered by the application. 
- Dynamic and unparmet queries are directly interpreted by the interpreter.
- Malicious data is used in the search parameters of the ORM, in order to steal data.
- The SQL command contains the malicious structure.

The most common injections are :
- SQL
- NoSQL
- OS command
- ORM (Object Relational Mapping)
- EL (Expression Language)
- OGNL (Object Graph Navigation Library)

To avoid having an application vulnerable to injections, you need to scan your code for possible weaknesses that make your application vulnerable to injection. This task can be automated by using static, dynamic and interactive security tools directly in the CI/CD pipeline to identify weaknesses and fix them before deployment. 

### How to Prevent
- use a secure API instead of an interpreter.
- providing a tightly parameterised interface or using an ORM. However, even well parameterised, this does not entirely avoid injections. 
- For all dynamic commands, use the special **"escape"** syntax which allows you to transform each user input into text, in order to avoid sending a query. However, for SQL structures it is not possible to use the **"escape"** syntax.
- Use tools such as SQL controls and LIMIT to avoid massive data leakage in case of injection.

### Exemple Attack Scenarios
#### Scenario 1
The application uses unsafe data in its SQL call. 

    $ String query = "SELECT \* FROM accounts WHERE custID='" + request.getParameter("id") + "'";
    
#### Scenario 2

The use of frameworks does not guarantee the 0 risk of having non-vulnerable requests.

    $  Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
    
In these two scenarios we can see that the attacker can easily modify the id parameter, which can lead in the worst case to data corruption or deletion.

## Sources

[A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)

[A05 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

[A06 Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)

[Heartbleed Bug](https://heartbleed.com/)

[CWE](https://cwe.mitre.org/)

----------

## CVE-2014-0160 Openssl heartbleed vulnerability

### SSL protocol

SSL pour Secure Socket Layer, est un protocole dévelopé par la compagnie Netscape Communication Corporation. Ce protocole permet aux applications client/serveur de communiquer de manière sécurisée. La version 3 introduite en 2003  est utilisée par les navigateurs. Ce protocole à connue une "évolution" créer par l'IETF (Internet Engineering Task Force) qui est le protocole TLS (Transport Layer Security)

### openSSL

OpenSSL est une boite à outils de cryptographie qui comporte deux biliothèques, libcrypto et libssl. oppenSSL implémente les protocoles SSL et TLS. Cette boite à outilis offre la possibilité de réaliser des application client/serveur sécurisées s'appuyant sur SSL et TLS. Il propose également une ligne de commande permettant notamant : 
- la création de clés RSA, DSA 
- chiffrement et déchiffrement 
- la signature et le chiffrement de courriers
- test de client et servers SSL/TLS
- création de certificats X509

### Heartbleed

Heartbleed est une vulnérabilité qui été découverte le 7 avril 2014 par des équipes de sécurité de Google et par des ingénieurs de l'entreprise finlandaise Codenomicon. Plus de 17% des serveur web soit environ un demi-million de serveur aurait été touché par cette vulnérabilité qui touche la bibliothèque de logiciel openSSL. Cette vulnérabilité a été introduite suite à une proposition de correction de bugs et d'améliorations de la version 1.0.1 d'openSSL. Les version d'openSSL qui ont été affecté sont de la 1.0.1 à 1.0.1f et 1.0.2-beta1. Heartbleed permet à l'attaquant de voler des données protégées par le cryptage SSL/TLS. Cette vulnérabilité permet à n'importe qu'elle personne sur Internet de lir la mémoir des sytèmes protégés. Il compromet :
- les clé secrètes
- les noms et mots de passe des utilisateurs
- l'intégrité du contenu
Les attaquants peuvent par ce moyen écouter des communications et volé des donnée directement à l'utilisateur et des services. Cela sans avoir à utiliser d'information ou d'identifiants privilégiés, selon les auteur du site internet [heartbleed.com](https://heartbleed.com/), qui ont menet des tests sur leurs services.

#### Comment fonctionne-t-elle ?

Les protocoles SSL et TLS possèdent une fonctionnalité que l'on nomme **"Heartbeat"**. Cette foncitonnalité permet à une extrimité d'une communication client ou server d'envoyer un message que l'interlocuteur va répéter en retour, afin de verfier que la connection est active et chiffrée. Le mesage envoyé par un client qui veut controller si le serveur est toujours actif, envoi le messge et un entier représentant la longueur du message. Suite à la sortie de la mise à 1.0.1, les développeurs d'oppenSSL n'ont pas mis un outils qui va vérifier que la longueur réel du message corresponde vraiment à l'indicateur de taille du message envoyer par le client.

Cette vulnérabilité est essentiellement basée sur le fait que le serveur ne vérifie pas l'entier correspondant à la taille du message et de ce fait à cause de la fonctionnalité **"Heartbeat"**, le serveur renvoit autant d'octest que demandé par le client. De ce fait, le client indique une taille du message plus grande que celle du message. Le serveur va donc combler le vide en retournant des information au hasard pour combler la différence. Soit des informations non utile, comme très sensible comme des clés privée de certificat, mots de passe et etc. 

L'attaquant ne sachant pas à l'avance les données que le serveur va renvoyer, il devra faire un tri des données qu'il juge utile ou pas.


#### Résolution

Le patch 1.0.1g d'openSSL corrige cette vulnérabilité. Il est donc recommandé de passer à cette version le plus rapidement possible.


----------

## SQLZoo
### 0 SELECT basics
#### Introducing the world table of countries

Pour afficher la population de l'Allemagne, j'ai changer la France par l'Allemagne comme le montre la commande ci-dessous.

    $ SELECT population FROM world WHERE name = 'Germany'
    
#### Scandinavia

Pour afficher la population de Sweden, Norway et Denmark, j'ai fait la commande ci-dessous en changeant le Brazil, la Russie et l'Inde par la Suède, la Norvège et le Danemark.

    $ SELECT name, population FROM world WHERE name IN ('Sweden', 'Norway', 'Denmark');
 
#### Just the right size

Pour afficher les pays ayant une taille se situant entre 200'000 et 250'500, j'ai fait la commande ci-dessous en changeant le 250'000 par 200'000 et 300'000 par 250'000.

    $ SELECT name, area FROM world WHERE area BETWEEN 200000 AND 250000

### 2 SELECT from World, from first subtask to 5 "France, Germany, Italy"
#### 1) Introduction

Pour afficher les noms, les continents et la population du monde, j'ai exécuté la commande ci-dessous.

    $ SELECT name, continent, population FROM world
    
#### 2) Large Countries

Pour afficher les noms des pays ayant une population d'au moins 200 million, j'ai exécuté la commande ci-dessous en modifiant 64'105'700 par 200'000'000 et en changeant le **"="** par **">="**.

    $ SELECT name FROM world WHERE population >= 200000000
   
#### 3) Per Capita GDP

Pour afficher les noms des pays et le PIB par habitant pour les pays ayant au moins une population de 200 million, j'ai effectué la commande ci-dessous.

    $ SELECT name, gdp/population FROM world WHERE population >= 200000000
    
#### 4) South America In millions

Pour afficher les noms et la population en million des pays se situant en Amérique du Sud, j'ai effectuer la commande suivante.

    $ SELECT name, population / 1000000 FROM world WHERE continent = 'South America'

#### 5) France, Germany, Italy

Pour afficher les noms et population de la France, L'Allemagne et l'Italie, j'ai effectuer la commande suivante : 

    $ SELECT name, population  FROM world Where name IN ('France', 'Germany', 'Italy')

#### 7) United

Pour afficher touts les noms des pays ayant le mot **"United"** dans leur nom, j'ai utilisé **"LIKE"** avec le symbole **"%"**. Le symbole **"%"** permet d'indiquer la position de la particule dans l'élément rechercher.

%test  : tous les éléments finissant par **"test"**.

test%  : tous les éléments commençant par **"test"**.

%test% : tous les éléments ayant dedans **"test"**


    $ SELECT name FROM world Where name LIKE '%United%'

## Sources

[0 SELECT basics](https://sqlzoo.net/wiki/SELECT_basics)

[2 SELECT from World](https://sqlzoo.net/wiki/SELECT_from_WORLD_Tutorial)

------------

## A1 Injection (intro)

### What is SQL ? exercices

For this exercise, I had to find the department of the employee **"Bob"** using the table **"employees"**. I performed the following command to find the department name.
 
     $ SELECT department FROM employees WHERE first_name = 'Bob';
     
### Data Manipulation Language (DML)

To change the department of the employee **"Tobi Barnett"**, I used the **"UPDATE"** command to change the department.

    $ UPDATE employees SET department = 'Sales' WHERE first_name = 'Tobi' and last_name = 'Barnett';
    
I have used the first and last name to avoid as much as possible confusion with a person who has an equivalent name or surname.

### Data Definition Language (DDL)

To add a new column to the table, use the SQL command**"ALTER TABLE "** to modify the table and then use the command **"ADD COLUMN"**. As shown in the command below.

    $ ALTER TABLE employees ADD COLUMN phone varchar(20);
    
### Data Control Language (DCL)

To change permissions in database management, it is easiest to create user groups with predefined permissions by the administrator. In this exercise, I had to allow the **"UnauthorizedUser"** group to modify the database tables. To do this I used the **"GRANT"** command which allows privileges to be set.

    $ GRANT ALTER TABLE TO UnauthorizedUser;
    
### Try It! String SQL injection

To do the injection, I based myself on the different examples presented in chapter 6 of **SQL Injection (intro)**. Also, reading the instructions I saw that knowing the specific name of a user was not necessary. With all this in mind, I issued this SQL command.

    $ SELECT * FROM user_data WHERE first_name = 'John' AND last_name = '' or '1' = '1'

According to the explanations, this injection works because **"or '1' = '1'"** is always evaluated as true.

### Try It! String SQL injection

In this exercise, we want to set up an SQL injection to get the full list of employees. To do this we need to find a way to create an SQL command that is always true. To do this I have made the command below. For this command it is not necessary to know a **"Login_Count "**, but we need to put the following formula **1 or true** to get an always true condition.

    $ SELECT * FROM user_data WHERE Login_Count = 1 and userid = 1 or true
 
### Compromising confidentiality with String SQL injection

In this exercise, we want to create an injection that allows us to access all the information of the employees. To do this we need to set up an SQL command that will always be true, as in the previous exercises.

    $ SELECT * FROM employees WHERE last_name = '' and auth_tan = '' or true ; --
    
### Compromising Integrity with Query chaining

In this exercise, we want to increase the salary of the employee **Smith**. To do this, we first need to close the first SQL command by using these " **' ;** " elements to set the last_name to null and close the SQL command. Then we can do a simple SQL command to **UPDATE** the employee's salary. This command will be followed by these **" -- "** symbols so that the following statements are ignored.

    $ SELECT * FROM employees WHERE lat_name = '' ; UPDATE employees SET salary = 90000 WHERE last_name = 'Smith'; --
    
### Compromising Availability

In order to cover our tracks, we need to clear the table containing all the logs. A log is generally a record of what the user does on the system.
To do this we need to use the SQL command **"DROP TABLE "** and as in the previous exercise, we need to close the previous SQL command. 

    $ SELECT * FROM employees WHERE lat_name = '' ; DROP TABLE access_log; --

## Sources

**WebGoat application** 
- SQL Injection (Intro)

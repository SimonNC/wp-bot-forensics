# Présentation — wp-bot-forensics

Support d'un oral de 5 minutes, suivi des questions qu'un analyste Threats Research
pourrait poser. Tous les chiffres viennent de [`analysis/FINDINGS.md`](analysis/FINDINGS.md).

## Oral de 5 minutes

### 1. Le contexte (0:00 – 0:40)

- Une semaine de logs Apache réels (13–20 octobre 2026) d'un site WordPress en production,
  site.example, une petite entreprise, derrière Cloudflare.
- La question : **qui atteint encore le serveur d'origine, et que peut prouver un analyste
  à partir des seuls logs ?**
- 27 864 requêtes, 863 adresses IP, 78 % de réponses 403.

### 2. La méthode (0:40 – 1:40)

- Pipeline Python : parsing, enrichissement ASN et pays, pseudonymisation des IP par HMAC,
  calcul d'indicateurs par IP, puis classification.
- **Des règles explicables d'abord.** Chaque verdict garde ses raisons, par exemple
  `declared=Jetpack; Jetpack_from=Reliance Jio; login_posts_10min=56`.
- Deux principes : **le comportement passe avant l'identité déclarée** (un nom de robot ne
  coûte rien), et **un datacenter est un indice, jamais un verdict**.
- Un Isolation Forest sert de filet de sécurité pour proposer de nouvelles règles. Il ne
  contredit jamais une règle.
- Elasticsearch et Kibana pour l'investigation ; DuckDB pour des analyses SQL versionnées
  et reproductibles.

### 3. Le constat principal : un botnet résidentiel (1:40 – 3:00)

*Montrer le panneau des réseaux du dashboard.*

- 43 IP chez des fournisseurs d'accès grand public et mobiles dans 21 pays (16 en Inde),
  **aucune dans un datacenter**, envoient 5 160 `POST /xmlrpc.php` : du credential stuffing.
- Elles se présentent comme le service Jetpack de WordPress.com, mais aucune ne vient du
  réseau d'Automattic.
- Signature d'une boucle scriptée : environ 56 tentatives par 10 minutes, un rythme quasi
  constant (coefficient de variation médian 0,05), et 25 d'entre elles s'arrêtent à
  exactement 150 tentatives, un quota par bot.
- Seules 10 des 43 se chevauchent dans le temps : la règle de campagne seule en aurait raté
  les trois quarts, c'est la règle de rafale par IP qui fait l'essentiel.

### 4. Ce que voit chaque couche de défense (3:00 – 3:40)

- 71 % des requêtes viennent de scanners de vulnérabilités (`.env`, `.git`, `wp-config`),
  dont 83 % du volume depuis les clouds de Microsoft et Google.
- Apache bloque 5 189 POST XML-RPC avant PHP ; WP Cerber n'enregistre que 14 refus XML-RPC.
  Cerber a bloqué ou signalé 92 des 159 scanners, mais aucun des 43 attaquants
  d'identifiants : **chaque couche ne voit qu'une partie de l'attaque**.

### 5. Validation et limites (3:40 – 4:40)

- Pas de vérité terrain : revue manuelle de 30 acteurs tirés par catégorie. Les règles sont
  d'accord avec moi sur **25 sur 30**.
- Quand une règle accuse, elle a raison 24 fois sur 25. Le point faible est le rappel :
  4 des 5 acteurs laissés en `unknown` étaient des bots.
- Un faux positif trouvé et corrigé : mes propres sessions admin étaient classées bot.
- Limites : la vérification des crawlers repose sur le nom du réseau, la détection des
  robots déclarés sur des mots-clés, et un seul site sur une semaine.

### 6. Ouverture (4:40 – 5:00)

- Prochaines étapes : plages d'IP publiées et DNS inverse pour les crawlers, empreinte du
  botnet au-delà du user-agent.
- Ce que j'en retiens pour le poste : partir de la donnée brute, expliquer chaque verdict,
  et mesurer honnêtement où les règles se trompent.

## Questions d'un analyste DataDome

### 1. « Comment savez-vous que vos règles ne bloquent pas des humains ? »

- Je ne le sais pas avec certitude : il n'y a pas de vérité terrain dans des logs réels.
- J'ai mesuré la précision par catégorie sur un échantillon stratifié : 24 accusations
  justes sur 25. L'erreur était un vrai Bingbot classé scanner pour une seule sonde.
- J'ai trouvé un vrai faux positif : mes sessions admin à 45 requêtes par minute. Leçon :
  « rapide et depuis une seule IP » ne veut pas dire « malveillant ».
- Recoupements avec les 403 du serveur et les verdicts de Cerber.
- Pour aller plus loin : appliquer les règles à un jeu de données public avec du vrai
  trafic humain pour mesurer le taux de faux positifs.

### 2. « Ces bots utilisent des IP résidentielles. Bloquer par IP, ça marche ? »

- Mal. Ces IP sont souvent derrière du CGNAT (Reliance Jio, par exemple) : bloquer l'IP
  bloquerait aussi de vrais clients, et l'attaquant change d'IP de toute façon.
- Ce qui trahit ce botnet n'est pas l'IP, c'est la **cohérence** : un user-agent qui
  revendique Jetpack depuis un réseau mobile indien, un rythme métronomique, un quota fixe
  de 150 tentatives, une seule cible.
- En périphérie, on dispose de signaux que mes logs n'ont pas : empreinte TLS, ordre et
  cohérence des en-têtes HTTP, signaux JavaScript côté navigateur, et la vue du même
  botnet sur de nombreux sites clients.

### 3. « Pourquoi l'IP comme unité d'analyse, et pas une session ? »

- Les scanners changent de user-agent à chaque requête : une session (IP, user-agent)
  éclaterait un même acteur en dizaines de faux acteurs.
- Le coût : plusieurs utilisateurs derrière une même IP (NAT, CGNAT, proxy d'entreprise)
  sont fusionnés. Sur ce site, peu d'humains atteignent l'origine, donc le risque est
  faible ; sur un site à fort trafic, il faudrait une session par cookie ou par empreinte.

### 4. « Comment vérifieriez-vous correctement un Googlebot ? »

- Aujourd'hui, je vérifie que l'IP appartient au réseau de l'opérateur (AS « Google LLC »).
  C'est nécessaire mais pas suffisant : une VM Google Cloud est aussi « Google LLC ».
- La bonne méthode : DNS inverse de l'IP (`*.googlebot.com`), puis DNS direct pour
  confirmer qu'il renvoie la même IP, ou comparaison avec les plages d'IP que Google,
  Bing ou OpenAI publient.
- C'est la première amélioration listée dans le README.

### 5. « Comment transposeriez-vous ça à de l'ATO ou de la création de faux comptes ? »

- Le credential stuffing XML-RPC est déjà une tentative de prise de contrôle de compte :
  mêmes signaux (rafales de POST sur une cible d'authentification, distribution sur de
  nombreuses IP pour rester sous les seuils par IP).
- Pour les faux comptes : indicateur n°13 (soumissions de formulaire répétées), auquel
  j'ajouterais le domaine de l'e-mail, la vitesse de remplissage du formulaire et la
  réutilisation d'empreintes entre inscriptions.
- En production, il faudrait passer du lot au temps réel : calculer les fenêtres glissantes
  au fil de l'eau et décider avant que la requête atteigne l'application.

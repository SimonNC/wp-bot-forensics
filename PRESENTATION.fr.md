# Présentation — wp-bot-forensics

Support d'un oral de 5 minutes, suivi des questions qu'un analyste Threats Research
pourrait poser. Tous les chiffres viennent de [`analysis/FINDINGS.md`](analysis/FINDINGS.md).

## Oral de 5 minutes

### 1. Le contexte (0:00 – 0:40)

- Une semaine de logs Apache réels (13–20 octobre 2026) du site WordPress d'une petite
  entreprise, en production derrière Cloudflare. Le site est anonymisé.
- La question : **qui atteint encore le serveur d'origine, et que peut prouver un analyste
  à partir des seuls logs ?**
- 27 864 requêtes, 863 adresses IP, 78 % de réponses 403.

### 2. La méthode (0:40 – 1:30)

- Pipeline Python : parsing, enrichissement ASN et pays, pseudonymisation des IP par HMAC,
  calcul d'indicateurs par IP, puis classification.
- **Des règles explicables d'abord.** Chaque verdict garde ses raisons, par exemple
  `declared=Jetpack; Jetpack_from=Reliance Jio; login_posts_10min=56`.
- Deux principes : **le comportement passe avant l'identité déclarée** (un nom de robot ne
  coûte rien), et **un datacenter est un indice, jamais un verdict**.
- Elasticsearch et Kibana pour l'investigation ; DuckDB pour des analyses SQL versionnées.

### 3. Constat 1 : des attaques par mots de passe via des proxies résidentiels (1:30 – 2:30)

*Montrer le panneau des réseaux du dashboard.*

- 43 IP chez des fournisseurs d'accès grand public et mobiles dans 21 pays, **aucune dans
  un datacenter** : probablement un réseau de proxies résidentiels loué.
- 5 160 tentatives de connexion sur `xmlrpc.php`. 39 de ces IP se présentent comme le
  service Jetpack de WordPress.com ; aucune ne vient de son réseau.
- Signature d'un outil : environ 56 tentatives par 10 minutes, un rythme quasi constant, et
  25 IP qui s'arrêtent à exactement 150 tentatives, un quota par bot.
- C'est une tentative de prise de contrôle de comptes. Sans le corps des requêtes, je ne
  peux pas dire si c'est du credential stuffing ou de la force brute.

### 4. Constat 2 : des scanners déguisés en crawlers IA (2:30 – 3:20)

- 6 IP Google Cloud, sur 4 jours, font tourner les mêmes 33 user-agents : GPTBot,
  ClaudeBot, PerplexityBot, DeepSeekBot, Googlebot… soit 24 noms de crawlers.
- Environ 400 requêtes en 12 à 14 secondes par IP, toutes à la recherche de `.env` et
  d'identifiants cloud. Rien de sensible n'a été servi.
- Ce n'est pas du trafic d'agents IA : c'est un scanner de secrets qui porte des masques
  de crawlers, sans doute pour passer les règles « autoriser les crawlers IA ».
- Leçon pour ma propre détection : depuis Google Cloud, leur faux Googlebot aurait passé
  ma vérification par ASN. C'est la limite que je corrigerais en premier.

### 5. Validation et limites (3:20 – 4:30)

- Pas de vérité terrain : revue manuelle de 30 acteurs tirés par catégorie. Les règles sont
  d'accord avec moi sur **25 sur 30**. Quand une règle accuse, elle a raison 24 fois sur 25 ;
  4 des 5 acteurs laissés en `unknown` étaient des bots. La précision est bonne, le rappel
  est le point faible.
- Un faux positif trouvé et corrigé : mes propres sessions admin étaient classées bot.
- Chaque couche ne voit qu'une partie de l'attaque : Apache refuse les 5 189 POST XML-RPC,
  le plugin de sécurité n'en enregistre que 14.
- Et surtout : des logs d'origine n'ont ni empreinte TLS, ni signal JavaScript. Un Chrome
  headless derrière un proxy résidentiel passerait ici pour un humain. Ces signaux se
  trouvent en amont, en périphérie.

### 6. Ouverture (4:30 – 5:00)

- Prochaines étapes : plages d'IP publiées et DNS inverse pour les crawlers, mesure du
  rappel avec un second annotateur.
- Ce que j'en retiens pour le poste : partir de la donnée brute, expliquer chaque verdict,
  et mesurer honnêtement où les règles se trompent.

## Questions d'un analyste DataDome

### 1. « Votre validation est circulaire, non ? »

- Oui, en partie : j'ai annoté les acteurs classés par mes propres règles, seul.
- Ce qu'elle mesure quand même : la précision par catégorie (24 accusations justes sur 25).
  L'erreur était un vrai Bingbot classé scanner pour une seule sonde.
- Ce qu'elle ne mesure pas : le rappel. Et l'accord sur les `unknown` n'est que de 1 sur 5.
- Prochaine étape : un second annotateur, et un échantillon tiré des `unknown` pour mesurer
  le rappel.
- Un vrai faux positif trouvé en route : mes sessions admin à 45 requêtes par minute.
  « Rapide et depuis une seule IP » ne veut pas dire « malveillant ».

### 2. « Que fait votre pipeline face à un Chrome headless à jour, derrière un proxy résidentiel, avec un user-agent cohérent ? »

- Rien, et je le documente dans le README. Des logs d'origine ne contiennent ni TLS, ni
  JavaScript, ni l'ordre des en-têtes.
- C'est la couche en périphérie qui voit ça : empreinte TLS, cohérence des en-têtes HTTP,
  signaux JavaScript côté navigateur, et la vue du même attaquant sur de nombreux sites.
- Ce que mes logs apportent quand même : le comportement dans la durée. Le quota de 150
  tentatives ou la rotation de 33 user-agents sont des empreintes d'outil qui survivent à
  un changement d'IP.

### 3. « Qui a écrit le code ? Expliquez-moi `rules.py`. »

- Je l'ai développé avec Claude Code, et je l'indique dans le README. J'ai choisi les
  indicateurs, l'ordre des règles et les seuils, validé 30 acteurs, et trouvé puis corrigé
  le faux positif sur mes sessions admin.
- Exemple de choix que je défends : les règles d'attaque passent avant la vérification
  d'identité. C'est pourquoi les faux GPTBot et ClaudeBot sortent en `vuln_scanner` et non
  en `spoofed_crawler` ; l'usurpation reste visible dans les raisons et dans un tableau
  dédié de `FINDINGS.md`.

### 4. « Comment vérifieriez-vous correctement un Googlebot ou un crawler IA ? »

- Aujourd'hui, je vérifie que l'IP appartient au réseau de l'opérateur (AS « Google LLC »).
  C'est nécessaire mais pas suffisant : les scanners déguisés venaient justement de Google
  Cloud, qui est aussi « Google LLC ».
- La bonne méthode : DNS inverse de l'IP (`*.googlebot.com`), puis DNS direct pour
  confirmer qu'il renvoie la même IP, ou comparaison avec les plages d'IP que les
  opérateurs publient (Google, Bing et OpenAI le font).
- Et la cohérence du comportement : un vrai crawler ne demande pas `/.env` 12 fois en
  12 secondes.

### 5. « Comment reliez-vous ça à la fraude, et à la prise de contrôle de comptes ? »

- Les attaques sur `xmlrpc.php` sont des tentatives de prise de contrôle de comptes : des
  rafales de connexions réparties sur de nombreuses IP pour rester sous les seuils par IP.
- C'est le début d'une chaîne que je connais côté fraude aux paiements : un compte pris
  sert ensuite à frauder. Mon expérience chez Fia-Net et BetClic portait sur la fin de cette
  chaîne ; ce projet regarde son début.
- Pour les faux comptes, j'ajouterais aux soumissions de formulaire répétées le domaine de
  l'e-mail, la vitesse de remplissage et la réutilisation d'empreintes entre inscriptions.
- En production, il faudrait passer du lot au temps réel : des fenêtres glissantes
  calculées au fil de l'eau, et une décision avant que la requête atteigne l'application.

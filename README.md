# MiniVpnCapture

Petit VPN local Android (meme principe que PCAPdroid) qui capture le trafic de l'appareil et **decode ce qui est lisible**.

## Utilisation
1. Ouvrir le dossier dans Android Studio (il genere le Gradle wrapper), lancer sur un telephone (minSdk 24).
2. Bouton "Application : ..." -> choisir l'application a ecouter (recherche par nom ou package), ou "Toutes les applications".
3. "Demarrer" -> accepter la demande VPN -> le journal se remplit. Seul le trafic de l'application choisie est capture (`addAllowedApplication`), le reste du telephone n'est pas touche.
4. "Stop" arrete la capture (actif uniquement pendant la capture ; le choix d'application est verrouille tant que ca tourne).

## Architecture
| Fichier | Role |
|---|---|
| `CaptureVpnService` | `Builder` (10.215.173.1/30, routes 0.0.0.0/1 + 128.0.0.0/1), lecture de la TUN, relais TCP/UDP avec `protect()` |
| `Packet` | Parse / construit les paquets IPv4, TCP, UDP (checksums) |
| `Decoder` | DNS, HTTP clair, SNI TLS, hex -> texte, Base64 -> texte, hash probable, hexdump |
| `AppPicker` | Dialogue de choix d'application (icones + recherche) |
| `CaptureLog` / `MainActivity` | Journal et ecran (choix d'app, Demarrer / Stop / Effacer, etat) |

## Ce qui est decode
- DNS (requetes + reponses, apprend IP -> domaine)
- HTTP en clair (en-tetes)
- Texte brut, texte encode en hexadecimal ou Base64
- Hexdump + ASCII pour le binaire

## Limites
- **TLS/HTTPS : non dechiffre** (il faudrait un MITM avec certificat installe). On voit seulement le SNI.
- Un hash (MD5, SHA...) n'est pas reversible : il est juste identifie.
- IPv4 seulement (l'IPv6 n'est pas route dans le VPN), pas de fragments IP.
- Chaque segment TCP est decode seul (pas de reassemblage), pas de retransmission : c'est un outil d'analyse, pas un VPN de production.
- A utiliser sur ton propre appareil et tes propres applications.

## Decodage du protocole de dispatch taxi (port 54442)

`TaxiProtocol` decode le flux TCP applicatif de l'appli de dispatch : le transport est du **texte
hexadecimal, une trame par ligne**. Le flux est reassemble ligne par ligne (les gros messages sont
coupes en plusieurs segments TCP) puis chaque trame est decodee :

| Message | Sens | Contenu |
|---|---|---|
| `J` | serveur -> app | **offre de course** : depart, arrivee, client, telephones, heure de prise en charge |
| `A` | app -> serveur | reponse a l'offre : `P` = acceptee, `T` = refusee / laissee passer |
| `V` / `v` | serveur / app | confirmation serveur / accuse de reception chauffeur |
| `a` | serveur -> app | course annulee ou retiree (hypothese) |
| `U` | app -> serveur | debut de course (drapeau 1) / fin de trajet (drapeau 0) |
| `B` | app -> serveur | points de trace GPS pendant la course |
| `d` | app -> serveur | cloture de la course (montants en centimes, hypothese) |
| `Z` | serveur -> app | courses / demandes annoncees par zone |
| `M`, `n` | serveur -> app | messages texte du dispatch |
| `E`, `p`, `q`, `b`, `F`... | app -> serveur | positions et etat (`L` libre, `I` indisponible, `s` en station, `C`/`D` en course) |

Positions : longitude et latitude sur 4 octets en millisiemes de seconde d'arc. Dates : ms epoch.
Case **"Tout afficher"** : montre aussi positions, tableaux de stations et accuses (masques par defaut).
Les numeros de telephone sont partiellement masques (`TaxiProtocol.maskPhones`).
Les champs marques *hypothese* sont deduits de l'observation, pas d'une specification.

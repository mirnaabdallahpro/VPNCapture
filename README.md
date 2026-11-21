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

# Clanker

Mrežni alat za CTF natjecanja koja zabranjuju korištenje AI alata, ali
dopuštaju normalan pristup internetu. Igrači se spajaju na hotspot koji
kontrolira organizator; DNS proxy propušta sav promet osim upita prema
poznatim AI servisima (ChatGPT, Claude, Gemini, Copilot, itd.), a
terminal dashboard uživo prikazuje spojene uređaje i njihove DNS upite.

## Status

Rana faza / MVP za testiranje. Trenutno gotovo:

- DNS proxy sa sinkhole listom AI domena i ključnih riječi (`guard/dns_proxy.py`)
- Terminal dashboard uživo: uređaji + zadnji DNS upiti (`guard/dashboard.py`)
- ARP-based popis spojenih uređaja (`guard/devices.py`)
- Legacy Windows hotspot helperi (`guard/hotspot.py`)
- **Eksperimentalno**, još nije spojeno u dashboard: SNI-based traffic monitor
  preko WinDivert-a, hvata pokušaje i kad klijent zaobiđe DNS (`guard/traffic_monitor.py`)

## Bitno ograničenje - pročitaj prije korištenja

Ovo je pomoćni alat za detekciju, **ne nepogrešiv sustav**. Ne hvata:

- **Mobilni podaci / tethering preko SIM-a** - taj promet nikad ne dotakne ovu mrežu
- **Lokalno pokrenut AI model bez interneta** (npr. Ollama) - nema mrežnog traga
- **VPN** koji tunelira sav promet - DNS proxy ne vidi stvarnu destinaciju
- **DNS-over-HTTPS** ako klijent ignorira DHCP DNS i koristi ugrađeni DoH
  (Firefox/Chrome to rade po defaultu) - ublažava se SNI slojem (faza 2),
  ali nije riješeno u ovom MVP-u

Ovo mora biti nadopunjeno pravilnikom natjecanja (potpisana izjava,
zabrana osobnih hotspotova, fizički nadzor). DNS upit prema AI domeni je
**signal za ručnu provjeru**, ne automatski dokaz za diskvalifikaciju
(netko može slučajno otvoriti anthropic.com iz znatiželje).

## Zahtjevi

- Python 3.10+
- Windows 11 (testirano za Mobile Hotspot / legacy hosted network)
- `pip install -r requirements.txt`

## Postavljanje hotspot-a

### Opcija A - legacy "hosted network" (skriptabilno)

Prvo provjeri podržava li tvoj WiFi adapter ovo (noviji Intel AX čipovi
često ne podržavaju):

```bash
python -m guard.main hotspot-check
```

Ako piše da je podržano:

```bash
python -m guard.main hotspot-start --ssid CTF-Test --password nekalozinka123
```

Zatim u **Postavke mreže i interneta > Promjena postavki adaptera** desni
klik na tvoj glavni internet adapter > Svojstva > kartica Dijeljenje >
uključi dijeljenje interneta za adapter "Microsoft Hosted Network Virtual
Adapter" (ovo je Internet Connection Sharing, ICS - Windows ga ne nudi
kroz `netsh`, mora se ručno u GUI-ju).

### Opcija B - Mobile Hotspot (GUI, radi na svim novijim laptopima)

1. Postavke > Mreža i internet > Mobile Hotspot > Uključi
2. Otvori adapter "Local Area Connection* X" (virtualni hotspot adapter)
   u Postavkama adaptera > Svojstva > IPv4 > ručno postavi DNS na
   `127.0.0.1` (IP tvog laptopa na kojem vrtiš `guard`)

## Pokretanje

```bash
python -m guard.main dns
```

Ovo diže DNS proxy na portu 53 i otvara dashboard. Spoji telefon na
hotspot, otvori bilo koju normalnu stranicu (treba raditi), pa probaj
`claude.ai` ili `chat.openai.com` (treba pasti / NXDOMAIN) - oba
pokušaja trebaju se pojaviti u dashboardu s tvog telefona (MAC adresa).

Provjera spojenih uređaja bez dashboarda:

```bash
python -m guard.main devices
```

## Održavanje blocklist-e

`config/blocklist.yaml` - dodaj domenu ili ključnu riječ i pokreni
ponovno (nema potrebe za izmjenom koda). Keyword match hvata i nove/
nepoznate poddomene, ali može false-positive-ati (npr. "llama" je i ime
životinje) - tretiraj alert kao naznaku, ne kao presudu.

## Sljedeći koraci (roadmap)

1. Spojiti `traffic_monitor.py` (SNI) u glavni dashboard kao drugi izvor
   signala, neovisan o DNS-u klijenta
2. Blokada poznatih DoH resolvera (SNI/IP za cloudflare-dns.com,
   dns.google...) da se ne zaobiđe DNS sloj
3. Automatsko/ručno blokiranje MAC adrese iz dashboarda
4. Za produkciju na natjecanju: OpenWrt ruter kao AP + ovaj laptop kao
   monitoring/kontrolna stanica (robusnije od laptopa kao jedinog AP-a)

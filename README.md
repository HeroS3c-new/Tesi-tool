
# DNS Encrypted Tunnel

Questo progetto permette di stabilire un canale di comunicazione crittografato utilizzando un tunnel DNS. I dati vengono cifrati e offuscati tramite i moduli `cloakify` e `decloakify`, permettendo il trasferimento di comandi e risposte attraverso richieste DNS.

## Funzionamento

Il tunnel è composto da due parti:
1. **Client** - Cifra il comando da inviare e lo invia al server tramite DNS.
2. **Server** - Riceve, decifra ed esegue il comando, restituendo la risposta criptata attraverso DNS.

### Tecnologie utilizzate

- **AES Encryption**: per proteggere i messaggi con crittografia simmetrica (AES-256).
- **cloakify.py**: offusca i dati cifrati in una serie di FQDN (Fully Qualified Domain Names).
- **decloakify.py**: recupera e decifra i dati dal formato FQDN, ripristinando il contenuto originale.

## Prerequisiti

1. **Python 3.6+**
2. **Pacchetto `pycryptodome`** per AES:
    ```bash
    pip install pycryptodome
    ```
3. **cloakify.py** e **decloakify.py** presenti nella directory.

## Installazione

1. Clonare il repository:
    ```bash
    git clone https://github.com/tuo_user/dns-encrypted-tunnel.git
    cd dns-encrypted-tunnel
    ```

2. Posizionare i file `cloakify.py`, `decloakify.py` e le relative ciphers (es. `ciphers/desserts`) nella cartella principale del progetto.

## Configurazione

- **Chiave AES**: Definire una chiave AES simmetrica nel client e nel server per la crittografia. Deve essere lunga 32 byte per AES-256.
  
  ```python
  key = b'TuaChiaveAES32byteQui__AESKeyExample'
  ```

- **File delle Ciphers**: Usare uno dei file di ciphers inclusi in `ciphers/` (es. `desserts`). Assicurarsi che client e server utilizzino la stessa cipher.

## Esecuzione

### 1. Avvio del Server

Il server deve essere in ascolto per ricevere i comandi dal client:

```bash
python server.py
```

### 2. Invio del Comando dal Client

Il client può inviare comandi da eseguire sul server:

```bash
python client.py
```

Inserisci il comando quando richiesto. Il comando sarà criptato, offuscato in FQDN e inviato come pacchetti DNS.

### 3. Ricezione della Risposta

Il server esegue il comando, cifra l’output, e lo reinvia tramite pacchetti DNS al client. Il client, a sua volta, lo decripta e mostra l'output.

## Struttura dei File

- `client.py`: Codice del client per criptare e inviare comandi al server.
- `server.py`: Codice del server per ricevere, decifrare ed eseguire comandi, poi inviare la risposta.
- `cloakify.py`: Modulo che converte i dati in una sequenza di FQDN.
- `decloakify.py`: Modulo che converte i FQDN offuscati nel dato originale.
- `aes_encrypt.py`: Modulo per crittografare e decrittografare i messaggi.

## Limitazioni

- **Latenza**: L’uso di pacchetti DNS e la crittografia introducono una latenza significativa, limitando la velocità di trasferimento.
- **Sicurezza**: Questo codice fornisce crittografia AES, ma è comunque vulnerabile a un’analisi avanzata di traffico (non è una VPN).

---

## Esempio di Utilizzo

### Esempio di comando dal client:

```bash
$ python client.py
Inserisci il comando da eseguire sul server: ls -la
```

Il client invia il comando offuscato al server tramite pacchetti DNS.

### Esempio di output del server:

```bash
Eseguo comando: ls -la
Risultato inviato al client.
```

Il server riceve e decifra il comando, esegue `ls -la` e invia l'output criptato al client tramite DNS.

## Avvertenze

Questo tool è pensato a scopo didattico per esplorare i concetti di offuscamento e crittografia tramite DNS. Non utilizzare per fini illeciti o in reti che non hai il permesso di monitorare.

--- 

## Autore

Creato da Loris
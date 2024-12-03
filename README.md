![image](logo.png)

Questo progetto permette di stabilire un canale di comunicazione crittografato utilizzando un tunnel DNS. I dati vengono cifrati e offuscati tramite i moduli `cloakify` e `decloakify`, permettendo il trasferimento di comandi e risposte attraverso richieste DNS.

## Funzionamento

Il tunnel è composto da due parti:
1. **Sender** - Cifra il comando da inviare e lo invia al server tramite DNS.
2. **Receiver** - Riceve, decifra ed esegue il comando, restituendo la risposta criptata attraverso DNS.

### Tecnologie utilizzate

- **AES Encryption**: per proteggere i messaggi con crittografia simmetrica (AES-256).
- **cloakify.py**: offusca i dati cifrati in una serie di FQDN (Fully Qualified Domain Names).
- **decloakify.py**: recupera e decifra i dati dal formato FQDN, ripristinando il contenuto originale.

## Prerequisiti (vale sia per client che per server)
    - Python3+
    - tcptunnel (solo su sistemi UNIX-like)
## Installazione

1. Clonare il repository:
    ```bash
    git clone https://github.com/HeroS3c-new/Tesi-tool.git
    cd Tesi-tool
    ```
2. Installare le librerie
    ```bash
    pip install -r requirements.txt
    ```

## Configurazione 
-  **Personalizzare la lista dei domini** per il cloaking: puoi modificare o creare una nuova lista di domini, questa andrà posizionata in entrambe le cartelle (del sender e del receiver) 'ciphers\'

- **Chiave AES**: Definire una chiave AES simmetrica nel client e nel server per la crittografia. Deve essere lunga 32 byte per AES-256.
  all'interno dei file aes_encrypt.py (presenti sia in Sender che in Receiver) puoi impostare una tua chiave di crittoigrafia diversa da quella di default:
  
  ```python
  key = b'TuaChiaveAES32byteQui__AESKeyExample'
  ```
  Assicurati di impostare la stessa chiave sia per il Sender che per il Receiver.
- **File delle Ciphers**: Usare uno dei file di ciphers inclusi in `ciphers/` (es. `common_fqdn/topWebsites`). Assicurarsi che sender e receiver utilizzino la stessa cipher.

## Esecuzione

### 1. Avvio del Server

Il server deve essere in ascolto per ricevere i comandi dal client:

```bash
cd Receiver
python receiver.py --run
```

### 2. Invio del Comando dal Client

Il client può inviare comandi da eseguire sul server:

```bash
cd Sender
python sender.py -d {ip_receiver}
```
Inserisci il comando quando richiesto. Il comando sarà criptato, offuscato in FQDN e inviato come pacchetti DNS.

Nota: puoi conoscere il tuo ip attraverso lo script del receiver con il comando 
```
python receiver.py --help
```


### 3. Ricezione della Risposta

Il server esegue il comando, cifra l’output, e lo reinvia tramite pacchetti DNS al client. Il client, a sua volta, lo decripta e mostra l'output.

## Struttura dei File

- `sender.py`: Codice del client per criptare e inviare comandi al server.
- `receiver.py`: Codice del server per ricevere, decifrare ed eseguire comandi, poi inviare la risposta.
- `cloakify.py`: Modulo che converte i dati in una sequenza di FQDN.
- `decloakify.py`: Modulo che converte i FQDN offuscati nel dato originale.
- `aes_encrypt.py`: Modulo per crittografare e decrittografare i messaggi.

## Limitazioni

- **Latenza**: L’uso di pacchetti DNS e la crittografia introducono una latenza significativa, limitando la velocità di trasferimento.
- **Sicurezza**: Questo codice fornisce crittografia AES, e una totale trasparenza ad un analisi dei pacchetti della rete in quanto le richieste DNS avvengono verso domini comuni e conosciuti, tuttavia vi sono dei pattern che se conosciuti e non modificati dall'aggressore possono essere riconosciuti (es. endOfTrasmission.google.com)


## Limitazione di responsabilità

Questo tool è pensato a scopo didattico per esplorare i concetti di offuscamento e crittografia tramite DNS ai fini di una tesi universitaria.
Non utilizzare per fini illeciti o in reti che non hai il permesso di monitorare.


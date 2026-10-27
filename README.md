# SentinelTriage

**Strumento di triage e correlazione degli alert di sicurezza sviluppato in Python, con dashboard interattiva in Streamlit.**

SentinelTriage è un progetto di cybersecurity sviluppato per elaborare alert di sicurezza, individuare schemi sospetti tra eventi correlati e raggruppare le attività in casi di indagine. Utilizza regole di correlazione e prioritizzazione per aiutare gli analisti a concentrarsi sugli eventi potenzialmente più rilevanti.


## Funzionalità principali

- **Parsing e validazione degli alert** — verifica gli alert JSON, controlla la presenza dei campi obbligatori, normalizza i timestamp in UTC e segnala i record non validi.
- **Deduplicazione degli alert** — identifica alert duplicati entro una finestra temporale di due minuti, preservando gli eventi di autenticazione fallita necessari alle analisi successive.
- **Correlazione degli eventi** — collega eventi potenzialmente correlati in base a utenti, indirizzi IP sorgente, host e finestre temporali.
- **Rilevamento di anomalie di autenticazione** — individua tentativi di accesso falliti ripetuti, potenziali attacchi di password spraying e sequenze di autenticazioni fallite seguite da un accesso riuscito.
- **Correlazione di eventi potenzialmente legati al phishing** — individua clic su link email sospetti seguiti da attività di rete insolite che coinvolgono lo stesso utente e host.
- **Prioritizzazione dei casi** — assegna una priorità ALTA, MEDIA o BASSA in base alle regole di rilevamento e alla gravità riportata negli alert.
- **Supporto all'indagine** — presenta riepiloghi dei casi, motivazioni del rilevamento, indicatori rilevanti, elementi da verificare e azioni investigative raccomandate.
- **Dashboard interattiva** — permette di esplorare i casi, consultare le priorità e analizzare gli eventi correlati.
- **Esportazione dei report** — genera report in formato JSON e HTML per l'analisi e la documentazione.
- **Test automatici** — utilizza il framework `unittest` di Python per verificare il comportamento del parser, della correlazione e del triage.

## Regole di rilevamento e correlazione

SentinelTriage implementa attualmente i seguenti scenari basati su regole:

| Scenario | Logica |
|---|---|
| Alert duplicati | Identifica alert ripetuti entro una finestra di due minuti. |
| Accesso fallito seguito da accesso riuscito | Correla tentativi di autenticazione falliti e successivi accessi riusciti per lo stesso utente e indirizzo IP sorgente entro dieci minuti. |
| Tentativi di accesso falliti ripetuti | Rileva almeno cinque tentativi falliti per lo stesso utente e indirizzo IP sorgente entro dieci minuti. |
| Potenziale password spraying | Rileva almeno cinque tentativi di autenticazione falliti verso almeno cinque username distinti dallo stesso indirizzo IP sorgente entro dieci minuti. |
| Possibile attività legata al phishing | Correla il clic su un link email con una connessione di rete insolita che coinvolge lo stesso utente e host entro trenta minuti. |

Questi rilevamenti si basano su regole configurate nel codice. Identificano schemi che meritano approfondimenti, ma non dimostrano autonomamente che un account o un sistema sia stato compromesso.

## Tecnologie utilizzate

- **Python** — parsing, validazione, correlazione degli eventi e triage.
- **Streamlit** — realizzazione della dashboard interattiva.
- **JSON** — formato dei dati di input e dei report strutturati.
- **HTML** — generazione di report consultabili tramite browser.
- **unittest** — esecuzione dei test automatici.

## Struttura del progetto

```text
sentinel-triage/
├── app.py
├── generate_alerts.py
├── requirements.txt
├── README.md
├── data/
│   └── sample_alerts.json
├── src/
│   ├── main.py
│   ├── parser.py
│   ├── correlator.py
│   └── triage.py
└── tests/
    ├── test_parser.py
    ├── test_correlator.py
    └── test_triage.py
```

## Installazione e avvio

### 1. Clonare il repository

```bash
git clone https://github.com/LarisaDinulescu/sentinel-triage.git
cd sentinel-triage
```

### 2. Creare e attivare un ambiente virtuale

Su Linux o macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Installare le dipendenze

```bash
pip install -r requirements.txt
```

### 4. Avviare lo strumento da terminale

```bash
python src/main.py
```

Il programma elabora il dataset di esempio e mostra i casi di triage individuati, insieme alle informazioni utili per l'indagine.

### 5. Avviare la dashboard

```bash
streamlit run app.py
```

Aprire nel browser l'indirizzo locale indicato nel terminale, normalmente:

```text
http://localhost:8501
```

La dashboard offre un'interfaccia interattiva per consultare gli alert e i casi di indagine, con funzionalità di esportazione dei report.

## Test automatici

Per eseguire la suite di test dalla cartella principale del progetto:

```bash
python -m unittest discover -s tests -v
```

I test verificano la validazione degli alert, la logica di correlazione degli eventi e il comportamento del sistema di triage.

## Dataset di esempio

Il dataset incluso contiene **121 alert**. Nell'esecuzione attuale del campione:

- 118 alert vengono accettati.
- 3 alert vengono rifiutati durante la validazione.
- Vengono generati 19 casi correlati.
- 46 alert accettati rimangono non associati a un caso.

Questi valori descrivono il dataset di esempio e non rappresentano benchmark delle prestazioni o misure dell'accuratezza dei rilevamenti.

## Ambito e limiti del progetto

SentinelTriage è un progetto didattico di cybersecurity e un prototipo per dimostrare concetti di triage e correlazione degli eventi di sicurezza.

- I rilevamenti dipendono dalle regole implementate, dai campi disponibili negli eventi e dalle finestre temporali configurate.
- Un rilevamento indica uno schema potenzialmente sospetto, non la conferma di un'attività malevola.
- Le priorità sono indicazioni di triage basate su regole, non punteggi di rischio calibrati.
- Lo strumento non sostituisce una piattaforma SIEM, un sistema di Endpoint Detection and Response (EDR) o un processo operativo completo di Security Operations Center (SOC).
- I dati inclusi sono destinati ai test e alle dimostrazioni.

## Possibili sviluppi futuri

Tra i possibili miglioramenti rientrano l'introduzione di ulteriori regole di rilevamento, timeline investigative più dettagliate, soglie di correlazione configurabili e integrazioni con fonti esterne di dati di sicurezza.

## Autrice

Progetto personale di portfolio sviluppato per approfondire l'analisi degli eventi di sicurezza, i fondamenti del detection engineering e l'automazione dei flussi di indagine in ambito cybersecurity.

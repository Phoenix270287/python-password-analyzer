# -*- coding: utf-8 -*-
import csv
import secrets
import string
import os
from collections import defaultdict
import datetime
import json
import time
import shutil
import webbrowser
from urllib.parse import urlparse
import sys # Necessario per sys.exit()

# --- Configurazione ---
PASSWORD_LENGTH = 16
DUPLICATE_ENTRIES_REPORT_FILENAME = 'duplicate_entries_removed_report.txt'
PASSWORD_CHANGES_REPORT_FILENAME = 'password_changes_report.txt'
MANUALLY_DELETED_REPORT_FILENAME = 'manually_deleted_entries_report.txt'
FINAL_CSV_FILENAME = 'passwords_final_for_import.csv'
STATE_FILENAME = 'password_review_state.json'
SAVE_INTERVAL = 25

# --- Codici Colore ANSI ---
COLOR_RESET = "\x1b[0m"; COLOR_RED = "\x1b[31m"; COLOR_GREEN = "\x1b[32m"; COLOR_YELLOW = "\x1b[33m"
COLOR_BLUE = "\x1b[34m"; COLOR_MAGENTA = "\x1b[35m"; COLOR_CYAN = "\x1b[36m"; COLOR_BOLD = "\x1b[1m"; COLOR_DIM = "\x1b[2m"
def colorize(text, color): return f"{color}{text}{COLOR_RESET}"

# --- Dizionario Stringhe Multilingua ---
# (ASSICURATI CHE IL DIZIONARIO STRINGS COMPLETO SIA PRESENTE QUI - Ometto per brevità)
STRINGS = {
    "choose_lang": "Scegli la lingua / Choose language ([1] Italiano / [2] English): ",
    "invalid_lang": "Scelta non valida / Invalid choice.",
    "startup_title": {
        "it": "* Analizzatore Pwd Chrome: Revisione Manuale, Azioni Bulk/Simili, Ricerca/Salto, Salva/Resume *",
        "en": "* Chrome Pwd Analyzer: Manual Review, Bulk/Similar Actions, Search/Jump, Save/Resume *"
    },
    "security_warning_header": { "it": "AVVISO DI SICUREZZA MOLTO IMPORTANTE:", "en": "VERY IMPORTANT SECURITY WARNING:" },
    "security_warning_show_pwd": { "it": "Lo script mostrerà TUTTE le password una per una nel terminale.", "en": "The script will display ALL passwords one by one in the terminal." },
    "security_warning_safe_env": { "it": "ASSICURATI DI ESSERE IN UN AMBIENTE SICURO E PRIVATO.", "en": "ENSURE YOU ARE IN A SAFE AND PRIVATE ENVIRONMENT." },
    "security_warning_view_opt": { "it": "L'opzione [V] mostrerà password multiple per lo stesso HOST.", "en": "The [V] option will show multiple passwords for the same HOST." },
    "security_warning_caution": { "it": "Procedi con ESTREMA cautela, specialmente con le opzioni di gruppo e ricerca/salto!", "en": "Proceed with EXTREME caution, especially with group and search/jump options!" },
    "feature_list_header": { "it": "Funzionalità:", "en": "Features:" },
    "feature_dedup": { "it": "Dedup URL Esatto (iniziale), Revisione MANUALE voci uniche (con AVVISO PWD RIUTILIZZATA),", "en": "Exact URL Dedup (initial), MANUAL review of unique entries (with REUSED PWD WARNING)," },
    "feature_actions": { "it": "Azioni [G](+opz. A/K/D/N simili), [K], [D], [O], [V], [F]ind, [J]ump (se avviso),", "en": "Actions [G](+opt. A/K/D/N similar), [K], [D], [O], [V], [F]ind, [J]ump (if warning)," },
    "feature_bulk": { "it": "Azioni Bulk Rimanenti [KA] Keep All, [DA] Delete All,", "en": "Remaining Bulk Actions [KA] Keep All, [DA] Delete All," },
    "feature_other": { "it": "Salvataggio/Ripresa stato, Colori, Backup.", "en": "Save/Resume state, Colors, Backup." },
    "file_info": { "it": "File CSV: {csv_path}, File Stato: {state_filename}", "en": "CSV File: {csv_path}, State File: {state_filename}" },
    "reports_header": { "it": "Report Generati:", "en": "Generated Reports:" },
    "report_dedup_file": { "it": "  - Duplicati URL Esatto/User: {filename}", "en": "  - Exact URL/User Duplicates: {filename}" },
    "report_gen_file": { "it": "  - Password Generate ('g'/'a'/'gf'/'gj'): {filename}", "en": "  - Generated Passwords ('g'/'a'/'gf'/'gj'): {filename}" },
    "report_del_file": { "it": "  - Voci Eliminate ('d'/'da'/'ds'/'df'/'dj'): {filename}", "en": "  - Deleted Entries ('d'/'da'/'ds'/'df'/'dj'): {filename}" },
    "output_header": { "it": "Output Finale (dopo modifiche manuali sui siti):", "en": "Final Output (after manual updates on websites):" },
    "output_csv_file": { "it": "  - CSV per Import: {filename}", "en": "  - CSV for Import: {filename}" },
    "err_critical_csv_not_found": { "it": "ERRORE CRITICO: File CSV '{path}' non esiste.", "en": "CRITICAL ERROR: CSV file '{path}' does not exist." },
    "err_check_path": { "it": "Controlla il percorso nella variabile 'csv_file_path'.", "en": "Check the path in the 'csv_file_path' variable." },
    "state_load_ok": { "it": "--- Stato precedente caricato da '{filename}'. Si riprende il lavoro. ---", "en": "--- Previous state loaded from '{filename}'. Resuming work. ---" },
    "state_last_entry": { "it": "--- (Ultima voce unica processata indice: {index}) ---", "en": "--- (Last unique entry processed index: {index}) ---" },
    "state_load_err": { "it": "ATTENZIONE: Errore durante il caricamento dello stato da '{filename}': {error}. Si inizia da capo.", "en": "WARNING: Error loading state from '{filename}': {error}. Starting over." },
    "state_load_err_rename": { "it": "File di stato rinominato in '{new_filename}'.", "en": "State file renamed to '{new_filename}'." },
    "state_load_not_found": { "it": "--- Nessun file di stato ('{filename}') trovato. Si inizia dall'inizio. ---", "en": "--- No state file ('{filename}') found. Starting from the beginning. ---" },
    "ask_backup": { "it": "Vuoi creare un backup di '{filename}'? ({yes}/{no}): ", "en": "Do you want to create a backup of '{filename}'? ({yes}/{no}): " },
    "backup_created": { "it": "Backup creato: '{filename}'", "en": "Backup created: '{filename}'" },
    "backup_skipped": { "it": "Nessun backup creato.", "en": "No backup created." },
    "err_backup": { "it": "Errore backup: {error}", "en": "Backup error: {error}" },
    "reading_csv": { "it": "Lettura del file CSV...", "en": "Reading CSV file..." },
    "err_csv_missing_cols": { "it": "Errore: Colonne richieste mancanti ('url', 'username', 'password').", "en": "Error: Required columns missing ('url', 'username', 'password')." },
    "err_csv_not_found": { "it": "Errore: File CSV '{path}' non trovato.", "en": "Error: CSV file '{path}' not found." },
    "err_csv_read": { "it": "Errore lettura CSV: {error}", "en": "Error reading CSV: {error}" },
    "no_csv_data": { "it": "Nessun dato trovato nel file CSV.", "en": "No data found in CSV file." },
    "no_review_entries": { "it":"Nessuna voce unica da revisionare.", "en": "No unique entries to review." },
    "read_entries_count": { "it": "Lette {count} voci totali.", "en": "Read {count} total entries." },
    "precalc_start": { "it": "Pre-calcolo raggruppamenti e conteggi password...", "en": "Pre-calculating groupings and password counts..." },
    "grouped_host_count": { "it": "Raggruppate voci per {count} HOST distinti.", "en": "Grouped entries by {count} distinct HOSTS." },
    "reused_pwd_count": { "it": "Trovate {count} password distinte riutilizzate in più voci.", "en": "Found {count} distinct passwords reused across multiple entries." },
    "dedup_exact_start": { "it": "Identificazione voci duplicate (URL ESATTO/Username)...", "en": "Identifying duplicate entries (EXACT URL/Username)..." },
    "dedup_exact_results": { "it": "Identificate {unique_count} voci uniche (o prime occorrenze URL/User) e {removed_count} voci duplicate esatte scartate.", "en": "Identified {unique_count} unique entries (or first URL/User occurrences) and {removed_count} exact duplicate entries discarded." },
    "report_gen_exec": { "it": "Generazione report duplicati URL ESATTO/User rimossi '{filename}'...", "en": "Generating exact URL/User duplicates removed report '{filename}'..." },
    "report_dedup_not_created": { "it": "Nessun duplicato esatto URL/User trovato. Report '{filename}' non creato.", "en": "No exact URL/User duplicates found. Report '{filename}' not created." },
    "report_dedup_title": { "it": "Report Rimozione Voci Duplicate (URL ESATTO/Username)", "en": "Duplicate Entries Removal Report (EXACT URL/Username)" },
    "report_dedup_desc1": { "it": "Queste voci avevano URL e Username ESATTAMENTE IDENTICI ad una voce precedente.", "en": "These entries had EXACTLY the same URL and Username as a previous entry." },
    "report_dedup_desc2": { "it": "È stata mantenuta solo la PRIMA occorrenza trovata nel file originale.", "en": "Only the FIRST occurrence found in the original file was kept." },
    "report_dedup_desc3": { "it": "Queste voci sono mostrate in [V]iew related (raggruppato per HOST) con l'etichetta [DUPLICATO URL/User RIMOSSO].", "en": "These entries are shown in [V]iew related (grouped by HOST) labeled [REMOVED URL/User DUPLICATE]." },
    "report_total_removed": { "it": "Totale voci duplicate rimosse: {count}", "en": "Total duplicate entries removed: {count}" },
    "report_saved": { "it": "Report salvato come '{filename}'.", "en": "Report saved as '{filename}'." },
    "err_report_write": { "it": "Errore scrittura report duplicati: {error}", "en": "Error writing duplicates report: {error}" },
    "review_start": { "it": "--- Inizio Revisione Manuale di {total} Voci Uniche (URL/User) ---", "en": "--- Starting Manual Review of {total} Unique Entries (URL/User) ---" },
    "review_actions_single": { "it": "Azioni Voce Singola: [G]enera, [K]eep, [D]elete, [O]pen URL, [V]iew related, [F]ind, [J]ump (se avviso)", "en": "Single Entry Actions: [G]enerate, [K]eep, [D]elete, [O]pen URL, [V]iew related, [F]ind, [J]ump (if warning)" },
    "review_actions_bulk": { "it": "Azioni Bulk Rimanenti: [KA] Keep All, [DA] Delete All (USA CON CAUTELA!)", "en": "Remaining Bulk Actions: [KA] Keep All, [DA] Delete All (USE WITH CAUTION!)" },
    "reviewing_entry": { "it": "--- Revisionando Voce {current} di {total} ---", "en": "--- Reviewing Entry {current} of {total} ---" },
    "label_name": { "it": "  Nome", "en": "  Name" },
    "label_url": { "it": "  URL", "en": "  URL" },
    "label_username": { "it": "  Username", "en": "  Username" },
    "label_password": { "it": "  Password Attuale", "en": "  Current Password" },
    "warn_reused_pwd": { "it": "❗ ATTENZIONE: Password Riutilizzata! Trovata in altre {count} voci:", "en": "❗ WARNING: Reused Password! Found in {count} other entries:" },
    "warn_reused_pwd_entry": { "it": "    [J{num}] [Idx Orig: {orig_idx}] User={user} su Host={host}", "en": "    [J{num}] [Orig Idx: {orig_idx}] User={user} on Host={host}" },
    "warn_reused_pwd_other": { "it": "...e altre {count}", "en": "...and {count} others" },
    "info_related_host": { "it": "INFO: Trovate {count} voci totali (originali) per questo HOST: {host}", "en": "INFO: Found {count} total (original) entries for this HOST: {host}" },
    "prompt_action": { "it": "Azione? [G]en/[K]eep/[D]el/[O]pen{v_part}/{f_part}{j_part} | [KA]KeepAll/[DA]DelAll: ", "en": "Action? [G]en/[K]eep/[D]el/[O]pen{v_part}/{f_part}{j_part} | [KA]KeepAll/[DA]DelAll: " },
    "prompt_action_view": { "it": "/[V]iew", "en": "/[V]iew" },
    "prompt_action_find": { "it": "/[F]ind", "en": "/[F]ind" },
    "prompt_action_jump": { "it": "/[J]ump", "en": "/[J]ump" },
    "err_invalid_response": { "it": "Risposta non valida.", "en": "Invalid response." },
    "action_open_attempt": { "it": "Tentativo apertura URL: {url}", "en": "Attempting to open URL: {url}" },
    "action_open_err": { "it": "Errore apertura URL: {error}", "en": "Error opening URL: {error}" },
    "action_open_invalid": { "it": "URL non valido per apertura.", "en": "Invalid URL for opening." },
    "action_gen_start": { "it": "OK. Generazione nuova password...", "en": "OK. Generating new password..." },
    "action_gen_done": { "it": "Password aggiornata in memoria per questa voce.", "en": "Password updated in memory for this entry." },
    "action_gen_show_pwd": { "it": "Nuova password generata: {password}", "en": "New password generated: {password}" },
    "info_found_similar": { "it": "INFO: Trovate {count} altre voci NON PROCESSATE con stesso HOST/USER:", "en": "INFO: Found {count} other UNPROCESSED entries with the same HOST/USER:" },
    "info_similar_entry_details": { "it": "    - Indice {index}: URL={url}, User={user}, Password Attuale={password}", "en": "    - Index {index}: URL={url}, User={user}, Current Password={password}" },
    "prompt_similar_action": { "it": "  Azione per queste {count} voci simili? [A]pplica NuovaPwd / [K]eep Attuali / [D]elete Tutte / [N]essuna Azione : ", "en": "  Action for these {count} similar entries? [A]pply NewPwd / [K]eep Current / [D]elete All / [N]o Action : " },
    "action_similar_apply_ok": { "it": "OK. Applicazione nuova password alle voci simili...", "en": "OK. Applying new password to similar entries..." },
    "action_similar_apply_done": { "it": "Password applicata a {count} voci simili. Saranno saltate.", "en": "Password applied to {count} similar entries. They will be skipped." },
    "action_similar_keep_ok": { "it": "OK. Mantenimento password attuali per voci simili...", "en": "OK. Keeping current passwords for similar entries..." },
    "action_similar_keep_done": { "it": "{count} voci simili saranno saltate mantenendo la loro password attuale.", "en": "{count} similar entries will be skipped, keeping their current passwords." },
    "action_similar_del_ok": { "it": "OK. Marcatura voci simili per eliminazione...", "en": "OK. Marking similar entries for deletion..." },
    "action_similar_del_done": { "it": "{count} voci simili marcate per eliminazione e saranno saltate.", "en": "{count} similar entries marked for deletion and will be skipped." },
    "action_similar_none_ok": { "it": "OK. Nessuna azione automatica. Le voci simili saranno processate separatamente.", "en": "OK. No automatic action. Similar entries will be processed separately." },
    "err_invalid_similar_action": { "it": "Risposta non valida.", "en": "Invalid response." },
    "action_keep_done": { "it": "OK. Password attuale MANTENUTA.", "en": "OK. Current password KEPT." },
    "action_del_done": { "it": "OK. Voce MARCATA per eliminazione.", "en": "OK. Entry MARKED for deletion." },
    "action_bulk_ka": { "it": "*** AZIONE BULK: KEEP ALL REMAINING ***", "en": "*** BULK ACTION: KEEP ALL REMAINING ***" },
    "action_bulk_ka_confirm": { "it": "Tutte le voci da indice {start} a {end} saranno considerate 'Keep'.", "en": "All entries from index {start} to {end} will be considered 'Keep'." },
    "action_bulk_da": { "it": "*** AZIONE BULK: DELETE ALL REMAINING ***", "en": "*** BULK ACTION: DELETE ALL REMAINING ***" },
    "action_bulk_da_confirm_q": { "it": "Sei SICURO di voler marcare TUTTE le {count} voci rimanenti per l'eliminazione? ({yes}/{no}): ", "en": "Are you SURE you want to mark ALL {count} remaining entries for deletion? ({yes}/{no}): " },
    "action_bulk_da_exec": { "it": "Marcatura voci rimanenti per l'eliminazione...", "en": "Marking remaining entries for deletion..." },
    "action_bulk_da_done": { "it": "{count} voci rimanenti marcate per l'eliminazione.", "en": "{count} remaining entries marked for deletion." },
    "action_bulk_cancel": { "it": "Azione annullata. Si continua con la revisione normale.", "en": "Action cancelled. Continuing normal review." },
    "review_end_manual": { "it": "--- Fine Revisione Manuale (tutte le voci processate) ---", "en": "--- End of Manual Review (all entries processed) ---" },
    "review_end_summary": { "it": "Revisionate {count} voci direttamente in questa sessione.", "en": "Reviewed {count} entries directly this session." },
    "review_end_skipped": { "it": "Saltate {count} voci processate automaticamente (via azioni simili o KA/DA).", "en": "Skipped {count} entries processed automatically (via similar actions or KA/DA)." },
    "review_end_recap": { "it": "Riepilogo azioni dirette: {g_count} G, {k_count} K, {d_count} D, {o_count} O, {v_count} V.", "en": "Direct action summary: {g_count} G, {k_count} K, {d_count} D, {o_count} O, {v_count} V." },
    "err_interrupt": { "it": "Interruzione rilevata (Ctrl+C).", "en": "Interrupt detected (Ctrl+C)." },
    "err_interrupt_state_saved": { "it": "Stato salvato fino alla voce {index}. Potrai riprendere.", "en": "State saved up to entry {index}. You can resume." },
    "err_interrupt_no_state": { "it": "Nessuna voce processata. Nessuno stato salvato.", "en": "No entries processed. No state saved." },
    "ops_final": { "it": "Operazioni finali...", "en": "Final operations..." },
    "report_gen_pwd_exec": { "it": "Generazione report password generate '{filename}'...", "en": "Generating generated passwords report '{filename}'..." },
    "report_gen_pwd_none": { "it": "Nessuna password generata ('g', 'a', 'gf', 'gj'). Report '{filename}' non creato.", "en": "No passwords generated ('g', 'a', 'gf', 'gj'). Report '{filename}' not created." },
    "report_gen_del_exec": { "it": "Generazione report voci eliminate manualmente '{filename}'...", "en": "Generating manually deleted entries report '{filename}'..." },
    "report_gen_del_none": { "it": "Nessuna voce eliminata manually ('d', 'da', 'ds', 'df', 'dj'). Report '{filename}' non creato.", "en": "No entries manually deleted ('d', 'da', 'ds', 'df', 'dj'). Report '{filename}' not created." },
    "ops_filtering_deleted": { "it": "Filtraggio voci marcate per l'eliminazione...", "en": "Filtering entries marked for deletion..." },
    "ops_remaining_final": { "it": "Voci rimanenti per il CSV finale: {count}", "en": "Entries remaining for final CSV: {count}" },
    "final_csv_writing": { "it": "Scrittura del file CSV finale '{filename}' ({count} voci)...", "en": "Writing final CSV file '{filename}' ({count} entries)..." },
    "err_final_csv_no_cols": { "it": "Errore: Colonne originali mancanti per CSV finale.", "en": "Error: Original columns missing for final CSV." },
    "err_final_csv_write": { "it": "Errore scrittura CSV finale '{filename}': {error}", "en": "Error writing final CSV '{filename}': {error}" },
    "final_csv_ok": { "it": "File CSV finale salvato come '{filename}'.", "en": "Final CSV file saved as '{filename}'." },
    "final_csv_warn_header": { "it": "AVVERTENZE IMPORTANTI per l'importazione:", "en": "IMPORTANT WARNINGS for import:" },
    "final_csv_warn1": { "it": "1. Il file '{filename}' contiene le voci mantenute ('k', 'ka') o aggiornate ('g', 'a', 'gf', 'gj').", "en": "1. File '{filename}' contains entries kept ('k', 'ka') or updated ('g', 'a', 'gf', 'gj')." },
    "final_csv_warn2": { "it": "   Le voci duplicate per URL ESATTO/Username sono state ridotte alla prima occorrenza.", "en": "   Exact URL/Username duplicate entries were reduced to the first occurrence." },
    "final_csv_warn3": { "it": "   Le voci che hai scelto di eliminare ('d', 'da', 'ds', 'df', 'dj') sono state Omesse.", "en": "   Entries you chose to delete ('d', 'da', 'ds', 'df', 'dj') have been Omitted." },
    "final_csv_warn_import": { "it": "2. **IMPORTALO IN CHROME SOLO DOPO AVER AGGIORNATO MANUALMENTE LE PASSWORD SUI SITI WEB!**", "en": "2. **IMPORT INTO CHROME ONLY AFTER MANUALLY UPDATING THE PASSWORDS ON THE WEBSITES!**" },
    "ops_state_deleted": { "it": "--- Processo completato. File stato '{filename}' eliminato. ---", "en": "--- Process completed. State file '{filename}' deleted. ---" },
    "err_state_delete": { "it": "ATTENZIONE: Impossibile eliminare file stato '{filename}': {error}", "en": "WARNING: Could not delete state file '{filename}': {error}" },
    "warn_state_delete": { "it": "Puoi eliminarlo manualmente.", "en": "You can delete it manually." },
    "script_terminated": { "it": "Script terminato.", "en": "Script finished." },
    "warn_state_exists_end": { "it": "** ATTENZIONE: Il file di stato {filename} esiste ancora. **", "en": "** WARNING: State file {filename} still exists. **" },
    "warn_state_exists_end_reason": { "it": "** Il processo potrebbe non essere stato completato o interrotto. **", "en": "** The process may not have completed successfully or was interrupted. **" },
    "warn_state_exists_end_cmd": { "it": "** Riesegui script per riprendere, o cancella {filename} per ricominciare. **", "en": "** Rerun script to resume, or delete {filename} to start over. **" },
    "search_mode_start": { "it": "--- Modalità Ricerca Voce ---", "en": "--- Entry Search Mode ---" },
    "search_prompt_term": { "it": "Inserisci termine di ricerca (parte di nome, URL o username): ", "en": "Enter search term (part of name, URL, or username): " },
    "search_empty_term": { "it": "Termine di ricerca vuoto.", "en": "Empty search term." },
    "search_no_results": { "it": "Nessuna voce attiva trovata per '{term}'.", "en": "No active entries found for '{term}'." },
    "search_results_header": { "it": "--- Risultati Ricerca Attuali ---", "en": "--- Current Search Results ---" },
    "search_result_line": { "it": "  {num}: [Indice Orig: {orig_idx}] URL={url}, User={user}", "en": "  {num}: [Orig Index: {orig_idx}] URL={url}, User={user}" },
    "search_no_valid_results": { "it": "Nessun risultato valido rimasto.", "en": "No valid results remaining." },
    "search_prompt_select": { "it": "Inserisci il numero del risultato su cui agire (1-{count}), o 0 per uscire dalla ricerca: ", "en": "Enter the result number to act on (1-{count}), or 0 to exit search: " },
    "search_err_invalid_num": { "it": "Inserisci un numero.", "en": "Enter a number." },
    "search_err_invalid_choice": { "it": "Numero non valido.", "en": "Invalid number." },
    "search_selected_header": { "it": "--- Dettagli Voce Selezionata (Indice Orig: {index}) ---", "en": "--- Selected Entry Details (Orig Index: {index}) ---" },
    "search_prompt_action": { "it": "Azione per questa voce cercata? [G]enera / [K]eep(Annulla) / [D]elete / [O]pen URL : ", "en": "Action for this searched entry? [G]enerate / [K]eep(Cancel) / [D]elete / [O]pen URL : " },
    "search_gen_ok": { "it": "Password aggiornata per voce {index}.", "en": "Password updated for entry {index}." },
    "search_gen_show_pwd": { "it": "Nuova password: {password}", "en": "New password: {password}" },
    "search_keep_ok": { "it": "Nessuna modifica apportata a questa voce.", "en": "No changes made to this entry." },
    "search_del_ok": { "it": "Voce {index} marcata per eliminazione.", "en": "Entry {index} marked for deletion." },
    "search_invalid_action": { "it": "Azione non valida per la ricerca.", "en": "Invalid action for search." },
    "search_mode_end": { "it": "--- Fine Modalità Ricerca ---", "en": "--- End Search Mode ---" },
    "jump_err_no_target": { "it": "Errore: Nessuna destinazione valida per il salto [J].", "en": "Error: No valid jump target [J]." },
    "jump_prompt_select": { "it": "Inserisci il numero [Jx] a cui saltare (1-{count}), o 0 per annullare il salto: ", "en": "Enter the number [Jx] to jump to (1-{count}), or 0 to cancel jump: " },
    "jump_err_invalid_choice": { "it": "Numero non valido.", "en": "Invalid number." },
    "jump_cancelled": { "it": "Salto annullato.", "en": "Jump cancelled." },
    "jump_no_unique_target": { "it": "Errore: Impossibile trovare la voce unica corrispondente all'indice originale {index} (potrebbe essere un duplicato rimosso o già eliminata).", "en": "Error: Cannot find the unique entry corresponding to original index {index} (it might be a removed duplicate or already deleted)." },
    "jump_selected_header": { "it": "--- Azione su Voce Saltata [Indice Orig: {index}] ---", "en": "--- Action on Jumped Entry [Orig Index: {index}] ---" },
    "jump_target_deleted": { "it": "Voce {index} è già marcata per l'eliminazione.", "en": "Entry {index} is already marked for deletion." },
    "jump_target_processed": { "it": "Voce {index} è già stata processata automaticamente.", "en": "Entry {index} has already been processed automatically." },
    "jump_prompt_action": { "it": "Azione per questa voce saltata? [G]enera / [K]eep(Nessuna Azione) / [D]elete / [O]pen URL : ", "en": "Action for this jumped entry? [G]enerate / [K]eep(No Action) / [D]elete / [O]pen URL : " },
    "jump_gen_ok": { "it": "Password aggiornata per voce {index}.", "en": "Password updated for entry {index}." },
    "jump_keep_ok": { "it": "Nessuna modifica apportata a questa voce.", "en": "No changes made to this entry." },
    "jump_del_ok": { "it": "Voce {index} marcata per eliminazione.", "en": "Entry {index} marked for deletion." },
    "jump_invalid_action": { "it": "Azione non valida.", "en": "Invalid action." },
    "jump_mode_end": { "it": "--- Fine Azione su Voce Saltata [Indice Orig: {index}] ---", "en": "--- End Action on Jumped Entry [Orig Index: {index}] ---" },
    "return_to_review": { "it": "--- Ritorno alla revisione della Voce {current} di {total} ---", "en": "--- Returning to review of Entry {current} of {total} ---" },
    "report_dedup_header": { "it": "* Report Rimozione Voci Duplicate (URL ESATTO/Username) *", "en": "* Duplicate Entries Removal Report (EXACT URL/Username) *" },
    "report_pwd_gen_header": { "it": "* Report Password Generate (Conferma 'g', 'a', 'gf', 'gj') *", "en": "* Generated Passwords Report ('g', 'a', 'gf', 'gj' confirmation) *" }, # Adjusted header key
    "report_pwd_gen_desc": { "it": "Elenco delle voci per cui hai scelto di generare una nuova password.", "en": "List of entries for which you chose to generate a new password." },
    "report_pwd_gen_important": { "it": "IMPORTANTE: Devi AGGIORNARE MANUALMENTE queste password sui rispettivi siti web!", "en": "IMPORTANT: You must MANUALLY UPDATE these passwords on the respective websites!" },
    "report_pwd_gen_total": { "it": "Totale voci con password generata/applicata: {count}", "en": "Total entries with generated/applied password: {count}" },
    "report_pwd_gen_method_label": { "it": "Metodo", "en": "Method" },
    "report_pwd_gen_method_direct": { "it": "G diretta", "en": "Direct G" },
    "report_pwd_gen_method_similar": { "it": "Via [A]pplica a Simili", "en": "Via [A]pply to Similar" },
    "report_pwd_gen_method_find": { "it": "Via Ricerca [F]", "en": "Via Search [F]" },
    "report_pwd_gen_method_jump": { "it": "Via Salto [J]", "en": "Via Jump [J]" },
    "report_del_header": { "it": "* Report Voci Eliminate Manualmente ('d', 'da', 'ds', 'df', 'dj') *", "en": "* Manually Deleted Entries Report ('d', 'da', 'ds', 'df', 'dj') *" },
    "report_del_desc": { "it": "Elenco delle voci che hai scelto di ELIMINARE.", "en": "List of entries you chose to DELETE." },
    "report_del_desc2": { "it": "Queste voci NON saranno incluse nel file CSV finale per l'importazione.", "en": "These entries WILL NOT be included in the final CSV file for import." },
    "report_del_total": { "it": "Totale voci eliminate manualmente: {count}", "en": "Total manually deleted entries: {count}" },
    "report_del_method_label": { "it": "Eliminata via", "en": "Deleted via" },
    # ... (Altre chiavi necessarie, se presenti nel codice omesso)
}


# --- Variabile Globale per la Lingua ---
LANG = 'it' # Default

# --- Funzione Genera Password ---
def generate_strong_password(length=PASSWORD_LENGTH):
    # (Codice invariato)
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password) and any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and any(c in string.punctuation for c in password)):
            return password

# --- Funzione Normalizza URL per Host ---
def normalize_host_from_url(url_string):
    # (Codice invariato)
    if not isinstance(url_string, str) or not url_string.strip(): return ""
    try:
        url_string_processed = url_string.strip()
        if '://' not in url_string_processed: url_string_to_parse = 'http://' + url_string_processed
        else: url_string_to_parse = url_string_processed
        parsed = urlparse(url_string_to_parse); host_part = parsed.netloc.lower()
        if not host_part: return url_string_processed.lower()
        host_only = host_part;
        if (parsed.scheme == 'http' and host_part.endswith(':80')) or \
           (parsed.scheme == 'https' and host_part.endswith(':443')):
           host_only = host_part.rsplit(':', 1)[0]
        scheme = parsed.scheme if parsed.scheme else ""; original_had_schema = '://' in url_string_processed
        if scheme and original_had_schema and scheme in ['http', 'https']: return f"{scheme}://{host_only}"
        elif scheme and original_had_schema: return f"{scheme}://{host_part}"
        elif host_only: return host_only
        else: return url_string_processed.lower()
    except Exception: return url_string.strip().lower()

# --- Funzioni Report ---
def write_removed_duplicates_report(removed_duplicates_list, report_filename, original_csv_path):
    global LANG, STRINGS
    if not removed_duplicates_list:
        print(f"\n{colorize(STRINGS['report_dedup_not_created'][LANG].format(filename=report_filename), COLOR_YELLOW)}")
        return
    print(f"\n{colorize(STRINGS['report_gen_exec'][LANG].format(filename=report_filename), COLOR_CYAN)}")
    try:
        with open(report_filename, mode='w', encoding='utf-8') as report_file:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            report_file.write("*"*65 + "\n") # Adjusted width based on content
            report_file.write(f"{STRINGS['report_dedup_header'][LANG]}\n")
            report_file.write("*"*65 + "\n")
            report_file.write(f"Generated on: {now}\n")
            report_file.write(f"Based on file: {os.path.abspath(original_csv_path)}\n")
            report_file.write(STRINGS['report_dedup_desc1'][LANG] + "\n")
            report_file.write(STRINGS['report_dedup_desc2'][LANG] + "\n")
            report_file.write(STRINGS['report_dedup_desc3'][LANG] + "\n\n")
            report_file.write(STRINGS['report_total_removed'][LANG].format(count=len(removed_duplicates_list)) + "\n")
            report_file.write("-" * 65 + "\n")
            for entry in removed_duplicates_list:
                 report_file.write(f"URL: {entry.get('url', 'N/A')}\n")
                 report_file.write(f"Username: {entry.get('username', 'N/A')}\n")
                 report_file.write(f"Password (hidden): ***\n")
                 report_file.write(f"Name: {entry.get('name', 'N/A')}\n")
                 report_file.write("-" * 65 + "\n")
        print(f"{colorize(STRINGS['report_saved'][LANG].format(filename=report_filename), COLOR_GREEN)}")
    except Exception as e:
        print(f"{colorize(STRINGS['err_report_write'][LANG].format(error=e), COLOR_RED)}")

def write_password_changes_report(password_changes_list, report_filename, original_csv_path):
    global LANG, STRINGS
    if not password_changes_list:
        print(f"\n{colorize(STRINGS['report_gen_pwd_none'][LANG].format(filename=report_filename), COLOR_YELLOW)}")
        return
    print(f"\n{colorize(STRINGS['report_gen_pwd_exec'][LANG].format(filename=report_filename), COLOR_CYAN)}")
    try:
        with open(report_filename, mode='w', encoding='utf-8') as report_file:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            report_file.write("*" * 57 + "\n") # Adjusted width based on content
            report_file.write(f"{STRINGS['report_pwd_gen_header'][LANG]}\n")
            report_file.write("*" * 57 + "\n")
            report_file.write(f"Generated on: {now}\n")
            report_file.write(f"Based on file: {os.path.abspath(original_csv_path)}\n")
            report_file.write(STRINGS['report_pwd_gen_desc'][LANG] + "\n")
            report_file.write(STRINGS['report_pwd_gen_important'][LANG] + "\n\n")
            report_file.write(STRINGS['report_pwd_gen_total'][LANG].format(count=len(password_changes_list)) + "\n")
            report_file.write("-" * 57 + "\n")
            for entry_info in password_changes_list:
                report_file.write(f"Name: {entry_info.get('name', 'N/A')}\n")
                report_file.write(f"URL: {entry_info.get('url', 'N/A')}\n")
                report_file.write(f"Username: {entry_info.get('username', 'N/A')}\n")
                report_file.write(f"NEW Generated Password: {entry_info.get('new_password', 'N/A')}\n")
                method = STRINGS['report_gen_method_direct'][LANG]
                if entry_info.get('applied_to_similar'): method = STRINGS['report_gen_method_similar'][LANG]
                elif entry_info.get('via_search'): method = STRINGS['report_gen_method_find'][LANG]
                elif entry_info.get('via_jump'): method = STRINGS['report_gen_method_jump'][LANG]
                report_file.write(f"{STRINGS['report_gen_method_label'][LANG]}: {method}\n")
                report_file.write("-" * 57 + "\n")
        print(f"{colorize(STRINGS['report_saved'][LANG].format(filename=report_filename), COLOR_GREEN)}")
    except Exception as e:
        print(f"{colorize(STRINGS['err_report_write'][LANG].replace('duplicati', 'password generate').format(error=e), COLOR_RED)}")

def write_manually_deleted_report(deleted_entries_list, report_filename, original_csv_path):
    global LANG, STRINGS
    if not deleted_entries_list:
        print(f"\n{colorize(STRINGS['report_gen_del_none'][LANG].format(filename=report_filename), COLOR_YELLOW)}")
        return
    print(f"\n{colorize(STRINGS['report_gen_del_exec'][LANG].format(filename=report_filename), COLOR_CYAN)}")
    try:
        with open(report_filename, mode='w', encoding='utf-8') as report_file:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            report_file.write("*" * 58 + "\n") # Adjusted width based on content
            report_file.write(f"{STRINGS['report_del_header'][LANG]}\n")
            report_file.write("*" * 58 + "\n")
            report_file.write(f"Generated on: {now}\n")
            report_file.write(f"Based on file: {os.path.abspath(original_csv_path)}\n")
            report_file.write(STRINGS['report_del_desc'][LANG] + "\n")
            report_file.write(STRINGS['report_del_desc2'][LANG] + "\n\n")
            report_file.write(STRINGS['report_del_total'][LANG].format(count=len(deleted_entries_list)) + "\n")
            report_file.write("-" * 58 + "\n")
            for entry_info in deleted_entries_list:
                 report_file.write(f"Name: {entry_info.get('name', 'N/A')}\n")
                 report_file.write(f"URL: {entry_info.get('url', 'N/A')}\n")
                 report_file.write(f"Username: {entry_info.get('username', 'N/A')}\n")
                 report_file.write(f"{STRINGS['report_del_method_label'][LANG]}: {entry_info.get('delete_method', 'd')}\n")
                 report_file.write("-" * 58 + "\n")
        print(f"{colorize(STRINGS['report_saved'][LANG].format(filename=report_filename), COLOR_GREEN)}")
    except Exception as e:
        print(f"{colorize(STRINGS['err_report_write'][LANG].replace('duplicati', 'voci eliminate').format(error=e), COLOR_RED)}")

# --- Funzione Scrittura CSV Finale ---
def write_final_output_csv(final_filtered_entries_list, output_filename, original_fieldnames):
    global LANG, STRINGS
    # Add missing STRINGS key check
    if not final_filtered_entries_list:
        no_final_entries_key = 'no_final_entries' # Define key name
        if no_final_entries_key not in STRINGS: # Add fallback if key is missing
             STRINGS[no_final_entries_key] = {'it':"Nessuna voce rimasta per CSV finale.", 'en':"No entries left for final CSV."}
        print(f"\n{colorize(STRINGS[no_final_entries_key][LANG], COLOR_YELLOW)}"); return
    if not original_fieldnames: print(f"\n{colorize(STRINGS['err_final_csv_no_cols'][LANG], COLOR_RED)}"); return
    print(f"\n{colorize(STRINGS['final_csv_writing'][LANG].format(filename=output_filename, count=len(final_filtered_entries_list)), COLOR_CYAN)}")
    try:
        internal_flags = ['_to_delete', '_processed_by_action']
        fieldnames_to_write = [f for f in original_fieldnames if f not in internal_flags]
        with open(output_filename, mode='w', newline='', encoding='utf-8') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=fieldnames_to_write, extrasaction='ignore')
            writer.writeheader()
            for entry in final_filtered_entries_list:
                entry_to_write = {k: v for k, v in entry.items() if k not in internal_flags}
                writer.writerow(entry_to_write)
        print(f"{colorize(STRINGS['final_csv_ok'][LANG].format(filename=output_filename), COLOR_GREEN)}")
        print(f"{colorize('---', COLOR_YELLOW)}")
        print(colorize(STRINGS['final_csv_warn_header'][LANG], COLOR_YELLOW))
        print(colorize(STRINGS['final_csv_warn1'][LANG].format(filename=output_filename), COLOR_YELLOW))
        print(colorize(STRINGS['final_csv_warn2'][LANG], COLOR_YELLOW))
        print(colorize(STRINGS['final_csv_warn3'][LANG], COLOR_YELLOW))
        print(colorize(STRINGS['final_csv_warn_import'][LANG], COLOR_RED + COLOR_BOLD))
        print(f"{colorize('---', COLOR_YELLOW)}")
    except Exception as e:
        print(f"{colorize(STRINGS['err_final_csv_write'][LANG].format(filename=output_filename, error=e), COLOR_RED)}")

# --- Funzioni Salva/Carica Stato ---
def save_state(state_data, filename=STATE_FILENAME):
    # (Codice invariato)
    try:
        with open(filename, 'w', encoding='utf-8') as f: json.dump(state_data, f, indent=4)
    except Exception as e: print(f"{colorize(f'ATTENZIONE: Errore salvataggio stato {filename}: {e}', COLOR_RED)}")

def load_state(filename=STATE_FILENAME):
    global LANG, STRINGS # Need LANG for messages
    if os.path.exists(filename):
        try:
            with open(filename, 'r', encoding='utf-8') as f: state_data = json.load(f)
            required_keys = ['unique_entries_being_processed', 'original_fieldnames', 'last_processed_index', 'all_entries_original', 'removed_duplicates_info']
            # Use simple error message for ValueError, handle KeyError if STRINGS isn't fully populated yet
            if not all(k in state_data for k in required_keys): raise ValueError(STRINGS.get('state_load_err_incomplete', {'it':'Stato incompleto/obsoleto','en':'Incomplete/outdated state'})[LANG])
            state_data.setdefault('changed_password_entries_for_report', []); state_data.setdefault('manually_deleted_entries_info', []); state_data.setdefault('removed_duplicates_info', [])
            print(f"\n{colorize(STRINGS['state_load_ok'][LANG].format(filename=filename), COLOR_GREEN)}")
            last_idx = state_data.get('last_processed_index', -1)
            print(f"{colorize(STRINGS['state_last_entry'][LANG].format(index=last_idx+1), COLOR_GREEN)}") # Show index+1 for user
            return state_data
        except Exception as e:
            print(f"{colorize(STRINGS['state_load_err'][LANG].format(filename=filename, error=e), COLOR_YELLOW)}")
            try:
                corrupted_filename = filename + ".corrupted_" + datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                os.rename(filename, corrupted_filename)
                print(f"{colorize(STRINGS['state_load_err_rename'][LANG].format(new_filename=corrupted_filename), COLOR_YELLOW)}")
            except OSError: pass
            return None
    else:
        print(f"\n{colorize(STRINGS['state_load_not_found'][LANG].format(filename=filename), COLOR_CYAN)}")
        return None

# --- Funzione Ausiliaria Aggiorna Mappa Password ---
def update_password_map(pass_map, all_entries_orig, changed_entry_ref, old_password, new_password):
    # (Codice invariato)
    original_indices = [idx for idx, entry in enumerate(all_entries_orig) if entry.get('url') == changed_entry_ref.get('url') and entry.get('username') == changed_entry_ref.get('username') and entry.get('name') == changed_entry_ref.get('name')]
    if old_password and old_password in pass_map:
        current_indices_in_map = list(pass_map[old_password]) # Iterate over a copy
        for orig_idx in original_indices:
            if orig_idx in current_indices_in_map:
                 try:
                     pass_map[old_password].remove(orig_idx)
                 except ValueError: # Should not happen if logic is correct, but safety
                     pass
        if not pass_map[old_password]: del pass_map[old_password]
    if new_password:
        for orig_idx in original_indices:
             if orig_idx not in pass_map[new_password]: # Avoid adding duplicates if multiple original entries match
                 pass_map[new_password].append(orig_idx)


# --- Funzione Ricerca Voce ---
def search_and_edit_entry(entries_list, changed_report, deleted_report, all_entries_original_ref, passwords_map_ref):
    global LANG, STRINGS
    print(f"\n{colorize(STRINGS['search_mode_start'][LANG], COLOR_CYAN + COLOR_BOLD)}")
    search_term = input(STRINGS['search_prompt_term'][LANG]).strip()
    if not search_term: print(colorize(STRINGS['search_empty_term'][LANG], COLOR_YELLOW)); return False
    search_term_lower = search_term.lower(); action_occurred_in_search = False
    initial_search_results = []
    for idx, entry in enumerate(entries_list):
        if entry.get('_to_delete') or entry.get('_processed_by_action'): continue
        name = entry.get('name', '').lower(); url = entry.get('url', '').lower(); username = entry.get('username', '').lower()
        if search_term_lower in name or search_term_lower in url or search_term_lower in username: initial_search_results.append(idx) # Store only index

    if not initial_search_results: print(colorize(STRINGS['search_no_results'][LANG].format(term=search_term), COLOR_YELLOW)); return False

    # Store original data for display, as entries_list might change during the loop
    results_data = {idx: entries_list[idx].copy() for idx in initial_search_results}
    active_indices = list(initial_search_results) # Indices we can still act on

    while True:
        print(f"\n{colorize(STRINGS['search_results_header'][LANG], COLOR_GREEN)}")
        display_map = {}; current_display_count = 0
        for idx in active_indices: # Iterate through indices still active in this search session
             # Check the *current* state in the main list
            current_entry_state = entries_list[idx]
            if not current_entry_state.get('_to_delete'):
                current_display_count += 1
                display_map[current_display_count] = idx # Map display number to original index
                # Use originally stored data for display consistency unless deleted
                display_entry = results_data[idx]
                print(colorize(STRINGS['search_result_line'][LANG].format(
                      num=current_display_count,
                      orig_idx=idx+1,
                      url=display_entry.get('url', 'N/A'),
                      user=display_entry.get('username','')
                    ), COLOR_YELLOW)) # Apply color to user here

        if current_display_count == 0: print(colorize(STRINGS['search_no_valid_results'][LANG], COLOR_YELLOW)); break

        try:
            choice_str = input(STRINGS['search_prompt_select'][LANG].format(count=current_display_count)).strip(); choice = int(choice_str)
            if choice == 0: break
            if 1 <= choice <= current_display_count: selected_original_idx = display_map[choice]
            else: print(colorize(STRINGS['search_err_invalid_choice'][LANG], COLOR_RED)); continue
        except ValueError: print(colorize(STRINGS['search_err_invalid_num'][LANG], COLOR_RED)); continue

        # Work on the entry directly from the main list using the selected index
        selected_entry = entries_list[selected_original_idx]
        print(f"\n{colorize(STRINGS['search_selected_header'][LANG].format(index=selected_original_idx+1), COLOR_BLUE)}")
        print(f"{STRINGS['label_name'][LANG]}: {selected_entry.get('name', 'N/A')}")
        s_url = selected_entry.get('url', 'N/A'); s_clickable_url = s_url
        if s_url != 'N/A' and s_url.strip(): s_clickable_url = f"\x1b]8;;{s_url}\x1b\\{s_url}\x1b]8;;\x1b\\"
        print(f"{STRINGS['label_url'][LANG]}: {s_clickable_url}"); print(f"{STRINGS['label_username'][LANG]}: {colorize(selected_entry.get('username', 'N/A'), COLOR_YELLOW)}"); s_pwd_old = selected_entry.get('password', ''); print(f"{STRINGS['label_password'][LANG]}: {colorize(s_pwd_old, COLOR_RED)}"); print("-" * 20)

        action_performed_on_this_item = False
        while not action_performed_on_this_item:
            search_action_prompt = STRINGS['search_prompt_action'][LANG]
            s_action_input = input(search_action_prompt).lower().strip()
            if s_action_input.startswith('g'):
                print(f"  {STRINGS['action_gen_start'][LANG].replace('...',' per voce cercata...')}") # Modify string slightly
                new_s_password = generate_strong_password()
                entries_list[selected_original_idx]['password'] = new_s_password # Modify main list
                changed_report.append({'name': selected_entry.get('name', 'N/A'), 'url': selected_entry.get('url', 'N/A'), 'username': selected_entry.get('username', 'N/A'), 'new_password': new_s_password, 'applied_to_similar': False, 'via_search': True, 'via_jump': False })
                print(colorize(STRINGS['search_gen_ok'][LANG].format(index=selected_original_idx+1), COLOR_GREEN)); print(f"  {colorize(STRINGS['search_gen_show_pwd'][LANG].format(password=new_s_password), COLOR_GREEN)}")
                update_password_map(passwords_map_ref, all_entries_original_ref, entries_list[selected_original_idx], s_pwd_old, new_s_password) # Pass updated entry ref
                action_occurred_in_search = True; action_performed_on_this_item = True
            elif s_action_input.startswith('k'): print(colorize(f"  {STRINGS['search_keep_ok'][LANG]}", COLOR_YELLOW)); action_performed_on_this_item = True
            elif s_action_input.startswith('d'):
                entries_list[selected_original_idx]['_to_delete'] = True # Modify main list
                # Find original entry to ensure correct data in report if modified before deletion
                original_entry_for_report = results_data.get(selected_original_idx, selected_entry) # Fallback to current if not found
                deleted_report.append({'name': original_entry_for_report.get('name', 'N/A'), 'url': original_entry_for_report.get('url', 'N/A'), 'username': original_entry_for_report.get('username', 'N/A'), 'delete_method': 'df' })
                print(colorize(STRINGS['search_del_ok'][LANG].format(index=selected_original_idx+1), COLOR_RED))
                update_password_map(passwords_map_ref, all_entries_original_ref, entries_list[selected_original_idx], s_pwd_old, None) # Pass updated entry ref
                action_occurred_in_search = True; action_performed_on_this_item = True
                # Remove from active search indices so it doesn't show again
                if selected_original_idx in active_indices: active_indices.remove(selected_original_idx)
            elif s_action_input.startswith('o'):
                if s_url != 'N/A' and s_url.strip():
                    try: print(f"  {colorize(STRINGS['action_open_attempt'][LANG].format(url=s_url), COLOR_BLUE)}"); webbrowser.open(s_url)
                    except Exception as wb_err: print(f"  {colorize(STRINGS['action_open_err'][LANG].format(error=wb_err), COLOR_RED)}")
                else: print(f"  {colorize(STRINGS['action_open_invalid'][LANG], COLOR_YELLOW)}")
            else: print(colorize(f"  {STRINGS['search_invalid_action'][LANG]}", COLOR_YELLOW))
    print(f"\n{colorize(STRINGS['search_mode_end'][LANG], COLOR_CYAN + COLOR_BOLD)}")
    return action_occurred_in_search

# --- Funzione Modifica Voce Specifica (usata da Salto J) ---
def edit_specific_entry(target_index, entries_list, changed_report, deleted_report, all_entries_original_ref, passwords_map_ref):
    global LANG, STRINGS
    if not (0 <= target_index < len(entries_list)): print(colorize(f"Error: Invalid index {target_index+1}", COLOR_RED)); return False
    entry_to_edit = entries_list[target_index] # Work directly on the entry in the main list
    if entry_to_edit.get('_to_delete'): print(colorize(STRINGS['jump_target_deleted'][LANG].format(index=target_index+1), COLOR_YELLOW)); return False
    # Allow editing even if processed by similar? User might want to override. Let's remove this check.
    # if entry_to_edit.get('_processed_by_action'): print(colorize(STRINGS['jump_target_processed'][LANG].format(index=target_index+1), COLOR_YELLOW)); return False

    print(f"\n{colorize(STRINGS['jump_selected_header'][LANG].format(index=target_index+1), COLOR_MAGENTA + COLOR_BOLD)}")
    print(f"{STRINGS['label_name'][LANG]}: {entry_to_edit.get('name', 'N/A')}")
    e_url = entry_to_edit.get('url', 'N/A'); e_clickable_url = e_url
    if e_url != 'N/A' and e_url.strip(): e_clickable_url = f"\x1b]8;;{e_url}\x1b\\{e_url}\x1b]8;;\x1b\\"
    print(f"{STRINGS['label_url'][LANG]}: {e_clickable_url}")
    print(f"{STRINGS['label_username'][LANG]}: {colorize(entry_to_edit.get('username', 'N/A'), COLOR_YELLOW)}")
    e_pwd_old = entry_to_edit.get('password', '')
    print(f"{STRINGS['label_password'][LANG]}: {colorize(e_pwd_old, COLOR_RED)}")
    if e_pwd_old and e_pwd_old in passwords_map_ref:
        password_locations = passwords_map_ref[e_pwd_old]
        # Find original indices matching the *current state* of the entry being edited
        current_original_indices = [idx for idx, entry in enumerate(all_entries_original_ref) if entry.get('url') == entry_to_edit.get('url') and entry.get('username') == entry_to_edit.get('username') and entry.get('password') == e_pwd_old and entry.get('name') == entry_to_edit.get('name') ]
        other_occurrences = len([loc_idx for loc_idx in password_locations if loc_idx not in current_original_indices])
        if other_occurrences > 0: print(f"  {colorize(STRINGS['warn_reused_pwd'][LANG].split(':',1)[0].replace('!', '').strip() + f'! ({other_occurrences})', COLOR_RED + COLOR_BOLD)}")
    print("-" * 20)

    action_occurred = False
    while True:
        edit_action_prompt = STRINGS['jump_prompt_action'][LANG]
        e_action_input = input(edit_action_prompt).lower().strip()
        if e_action_input.startswith('g'):
            print(f"  {STRINGS['action_gen_start'][LANG].replace('...',' per voce saltata...')}")
            new_e_password = generate_strong_password()
            entries_list[target_index]['password'] = new_e_password # Modify main list
            changed_report.append({'name': entry_to_edit.get('name', 'N/A'), 'url': entry_to_edit.get('url', 'N/A'), 'username': entry_to_edit.get('username', 'N/A'), 'new_password': new_e_password, 'applied_to_similar': False, 'via_search': False, 'via_jump': True })
            print(colorize(STRINGS['jump_gen_ok'][LANG].format(index=target_index+1), COLOR_GREEN)); print(f"  {colorize(STRINGS['search_gen_show_pwd'][LANG].format(password=new_e_password), COLOR_GREEN)}")
            update_password_map(passwords_map_ref, all_entries_original_ref, entries_list[target_index], e_pwd_old, new_e_password) # Pass updated entry ref
            action_occurred = True; break
        elif e_action_input.startswith('k'): print(colorize(f"  {STRINGS['jump_keep_ok'][LANG]}", COLOR_YELLOW)); break
        elif e_action_input.startswith('d'):
            entries_list[target_index]['_to_delete'] = True # Modify main list
            deleted_report.append({'name': entry_to_edit.get('name', 'N/A'), 'url': entry_to_edit.get('url', 'N/A'), 'username': entry_to_edit.get('username', 'N/A'), 'delete_method': 'dj' })
            print(colorize(STRINGS['jump_del_ok'][LANG].format(index=target_index+1), COLOR_RED))
            update_password_map(passwords_map_ref, all_entries_original_ref, entries_list[target_index], e_pwd_old, None) # Pass updated entry ref
            action_occurred = True; break
        elif e_action_input.startswith('o'):
            if e_url != 'N/A' and e_url.strip():
                try: print(f"  {colorize(STRINGS['action_open_attempt'][LANG].format(url=e_url), COLOR_BLUE)}"); webbrowser.open(e_url)
                except Exception as wb_err: print(f"  {colorize(STRINGS['action_open_err'][LANG].format(error=wb_err), COLOR_RED)}")
            else: print(f"  {colorize(STRINGS['action_open_invalid'][LANG], COLOR_YELLOW)}")
        else: print(colorize(f"  {STRINGS['jump_invalid_action'][LANG]}", COLOR_YELLOW))
    print(f"{colorize(STRINGS['jump_mode_end'][LANG].format(index=target_index+1), MAGENTA + COLOR_BOLD)}")
    return action_occurred


# --- Funzione principale ---
def process_password_file(csv_filepath):
    global LANG, STRINGS
    # --- Stampa Iniziale / Avvisi ---
    print("\n" + "="*70); print(colorize(STRINGS['security_warning_header'][LANG], COLOR_RED + COLOR_BOLD)); print(colorize(STRINGS['security_warning_show_pwd'][LANG], COLOR_YELLOW)); print(colorize(STRINGS['security_warning_safe_env'][LANG], COLOR_YELLOW)); print(colorize(STRINGS['security_warning_view_opt'][LANG], COLOR_YELLOW)); print(colorize(STRINGS['security_warning_caution'][LANG], COLOR_RED + COLOR_BOLD)); print("="*70 + "\n")

    loaded_state = load_state(STATE_FILENAME)
    resuming = loaded_state is not None

    # --- Caricamento/Setup Dati ---
    if resuming:
        unique_entries_being_processed = loaded_state.get('unique_entries_being_processed', []); all_entries_original = loaded_state.get('all_entries_original', []); original_fieldnames = loaded_state.get('original_fieldnames', []); last_processed_index = loaded_state.get('last_processed_index', -1); changed_password_entries_for_report = loaded_state.get('changed_password_entries_for_report', []); manually_deleted_entries_info = loaded_state.get('manually_deleted_entries_info', []); removed_duplicates_info = loaded_state.get('removed_duplicates_info', []); start_index = last_processed_index + 1
    else:
        # Backup
        print(STRINGS['file_info'][LANG].format(csv_path=csv_filepath, state_filename=STATE_FILENAME).split(',')[0])
        while True:
            yes_char = 'y' if LANG == 'en' else 's'; no_char = 'n'; backup_prompt_text = STRINGS['ask_backup'][LANG].format(filename=os.path.basename(csv_filepath), yes=yes_char, no=no_char)
            backup_choice = input(backup_prompt_text).lower().strip()
            if backup_choice.startswith(yes_char):
                try: timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S"); backup_filename = f"{os.path.splitext(csv_filepath)[0]}_{timestamp}.csv.bak"; shutil.copy2(csv_filepath, backup_filename); print(colorize(STRINGS['backup_created'][LANG].format(filename=backup_filename), COLOR_GREEN))
                except Exception as e: print(colorize(STRINGS['err_backup'][LANG].format(error=e), COLOR_RED))
                break
            elif backup_choice.startswith(no_char): print(colorize(STRINGS['backup_skipped'][LANG], COLOR_YELLOW)); break
            else: print(colorize(STRINGS['err_invalid_response'][LANG], COLOR_YELLOW))
        # Lettura CSV
        all_entries_original = []; required_columns = ['url', 'username', 'password']; original_fieldnames = []
        print(f"\n{colorize(STRINGS['reading_csv'][LANG], COLOR_CYAN)}")
        try:
            # Use 'utf-8-sig' to handle potential BOM
            with open(csv_filepath, mode='r', encoding='utf-8-sig') as csvfile:
                reader = csv.DictReader(csvfile); original_fieldnames = reader.fieldnames
                if not original_fieldnames or not all(col in original_fieldnames for col in required_columns): print(colorize(STRINGS['err_csv_missing_cols'][LANG], COLOR_RED)); return
                all_entries_original = [entry.copy() for entry in reader]
        except FileNotFoundError: print(colorize(STRINGS['err_csv_not_found'][LANG].format(path=csv_filepath), COLOR_RED)); return
        except Exception as e: print(colorize(STRINGS['err_csv_read'][LANG].format(error=e), COLOR_RED)); return
        if not all_entries_original: print(colorize(STRINGS['no_csv_data'][LANG], COLOR_YELLOW)); return
        print(STRINGS['read_entries_count'][LANG].format(count=len(all_entries_original)))
        # De-duplicazione
        print(f"\n{colorize(STRINGS['dedup_exact_start'][LANG], COLOR_CYAN)}")
        unique_entries_being_processed = []; removed_duplicates_info = []; seen_combinations = set()
        for entry in all_entries_original:
            exact_url = entry.get('url', '').strip(); username = entry.get('username', '').strip(); username_lower = username.lower()
            # Consider empty username/url as unique? Or skip? Let's keep them.
            # if not exact_url or not username: unique_entries_being_processed.append(entry.copy()); continue
            entry_key = (exact_url, username_lower)
            if entry_key not in seen_combinations: seen_combinations.add(entry_key); unique_entries_being_processed.append(entry.copy())
            else: removed_duplicates_info.append(entry.copy())
        print(STRINGS['dedup_exact_results'][LANG].format(unique_count=len(unique_entries_being_processed), removed_count=len(removed_duplicates_info)))
        write_removed_duplicates_report(removed_duplicates_info, DUPLICATE_ENTRIES_REPORT_FILENAME, csv_filepath)
        changed_password_entries_for_report = []; manually_deleted_entries_info = []; start_index = 0

    # --- Pre-calcolo mappe ---
    print(f"\n{colorize(STRINGS['precalc_start'][LANG], COLOR_CYAN)}")
    entries_by_host = defaultdict(list); passwords_map = defaultdict(list)
    for idx, entry in enumerate(all_entries_original): # Use original entries for map
        host_key = normalize_host_from_url(entry.get('url', '')); password = entry.get('password', '')
        if host_key: entries_by_host[host_key].append(entry)
        if password: passwords_map[password].append(idx) # Store original index
    print(STRINGS['grouped_host_count'][LANG].format(count=len(entries_by_host)))
    reused_password_count = sum(1 for indices in passwords_map.values() if len(indices) > 1)
    print(STRINGS['reused_pwd_count'][LANG].format(count=reused_password_count))

    # --- Revisione Manuale ---
    if not unique_entries_being_processed: print(f"\n{colorize(STRINGS['no_review_entries'][LANG], COLOR_YELLOW)}"); return
    total_unique_entries = len(unique_entries_being_processed)
    print(f"\n{colorize(STRINGS['review_start'][LANG].format(total=total_unique_entries), COLOR_BLUE)}")
    print(colorize(STRINGS['review_actions_single'][LANG], COLOR_CYAN))
    print(colorize(STRINGS['review_actions_bulk'][LANG], COLOR_YELLOW))

    entries_processed_this_session = 0; entries_generated_count = 0; entries_kept_count = 0; entries_deleted_count = 0; entries_opened_count = 0; entries_viewed_count = 0; entries_skipped_auto = 0
    completed_successfully = False; current_index = -1

    try:
        for index in range(start_index, total_unique_entries):
            current_index = index
            # Use a reference that can be updated if edited via search/jump
            entry_to_process = unique_entries_being_processed[index]

            if entry_to_process.get('_to_delete') or entry_to_process.get('_processed_by_action'):
                entries_skipped_auto +=1
                continue

            entries_processed_this_session += 1
            print(f"\n{colorize(STRINGS['reviewing_entry'][LANG].format(current=index + 1, total=total_unique_entries), COLOR_BOLD + COLOR_BLUE)}")
            print(f"{STRINGS['label_name'][LANG]}: {entry_to_process.get('name', 'N/A')}")
            url_value = entry_to_process.get('url', 'N/A'); clickable_url_str = url_value
            if url_value != 'N/A' and url_value.strip(): clickable_url_str = f"\x1b]8;;{url_value}\x1b\\{url_value}\x1b]8;;\x1b\\"
            print(f"{STRINGS['label_url'][LANG]}: {clickable_url_str}")
            print(f"{STRINGS['label_username'][LANG]}: {colorize(entry_to_process.get('username', 'N/A'), COLOR_YELLOW)}")
            current_password = entry_to_process.get('password', '')
            print(f"{STRINGS['label_password'][LANG]}: {colorize(current_password, COLOR_RED)}")

            # --- Avviso Password Riutilizzata ---
            show_jump_option = False; jump_map = {}; other_occurrences = 0
            if current_password and current_password in passwords_map:
                 password_locations = passwords_map[current_password]
                 # Find original indices matching this unique entry's key properties
                 current_original_indices = [idx_orig for idx_orig, entry in enumerate(all_entries_original) if entry.get('url') == entry_to_process.get('url') and entry.get('username') == entry_to_process.get('username') and entry.get('password') == entry_to_process.get('password') and entry.get('name') == entry_to_process.get('name')]
                 other_indices = [loc_idx for loc_idx in password_locations if loc_idx not in current_original_indices]
                 other_occurrences = len(other_indices)
                 if other_occurrences > 0:
                    print(f"  {colorize(STRINGS['warn_reused_pwd'][LANG].format(count=other_occurrences), COLOR_RED + COLOR_BOLD)}")
                    show_jump_option = True; displayed_others = 0
                    for jump_num, loc_idx in enumerate(other_indices, 1):
                        if displayed_others < 5:
                             other_entry = all_entries_original[loc_idx]; other_host = normalize_host_from_url(other_entry.get('url','')); other_user = other_entry.get('username','')
                             print(colorize(STRINGS['warn_reused_pwd_entry'][LANG].format(num=jump_num, orig_idx=loc_idx+1, user=other_user, host=other_host), COLOR_MAGENTA)); jump_map[jump_num] = loc_idx; displayed_others += 1
                        else: break
                    if other_occurrences > displayed_others: print(f"    {colorize(STRINGS['warn_reused_pwd_other'][LANG].format(count=other_occurrences - displayed_others), COLOR_DIM)}")

            # --- Info Host Correlato ---
            related_entries = []; show_view_option_v = False
            current_url_raw = entry_to_process.get('url', ''); current_host_key = normalize_host_from_url(current_url_raw)
            if current_host_key and current_host_key in entries_by_host:
                related_entries = entries_by_host[current_host_key]
                if len(related_entries) > 1: show_view_option_v = True; print(f"  {colorize(STRINGS['info_related_host'][LANG].format(count=len(related_entries), host=current_host_key), COLOR_MAGENTA)}")

            # --- Loop Richiesta Azione ---
            while True:
                v_part = colorize(STRINGS['prompt_action_view'][LANG], COLOR_MAGENTA) if show_view_option_v else ""
                f_part = colorize(STRINGS['prompt_action_find'][LANG], COLOR_CYAN)
                j_part = colorize(STRINGS['prompt_action_jump'][LANG], COLOR_MAGENTA) if show_jump_option else ""
                prompt_text = STRINGS['prompt_action'][LANG].format(v_part=v_part, f_part=f_part, j_part=j_part)
                user_input = input(prompt_text).lower().strip()
                action = None

                if user_input.startswith('ka'): action = 'keep_all'; break
                elif user_input.startswith('da'): action = 'delete_all'; break
                elif user_input.startswith('f'):
                    search_modified = search_and_edit_entry(unique_entries_being_processed, changed_password_entries_for_report, manually_deleted_entries_info, all_entries_original, passwords_map)
                    print(f"\n{colorize(STRINGS['return_to_review'][LANG].format(current=index + 1, total=total_unique_entries), COLOR_BLUE)}")
                    entry_to_process = unique_entries_being_processed[index]; current_password = entry_to_process.get('password', '') # Reload
                    print(f"{STRINGS['label_name'][LANG]}: {entry_to_process.get('name', 'N/A')}")
                    url_value = entry_to_process.get('url', 'N/A'); clickable_url_str = url_value
                    if url_value != 'N/A' and url_value.strip(): clickable_url_str = f"\x1b]8;;{url_value}\x1b\\{url_value}\x1b]8;;\x1b\\"
                    print(f"{STRINGS['label_url'][LANG]}: {clickable_url_str}")
                    print(f"{STRINGS['label_username'][LANG]}: {colorize(entry_to_process.get('username', 'N/A'), COLOR_YELLOW)}")
                    print(f"{STRINGS['label_password'][LANG]}: {colorize(current_password, COLOR_RED)}")
                    # Recalculate jump options
                    show_jump_option = False; jump_map = {}
                    if current_password and current_password in passwords_map:
                        password_locations = passwords_map[current_password]
                        current_original_indices = [idx_orig for idx_orig, entry in enumerate(all_entries_original) if entry.get('url') == entry_to_process.get('url') and entry.get('username') == entry_to_process.get('username') and entry.get('password') == entry_to_process.get('password') and entry.get('name') == entry_to_process.get('name')]
                        other_indices = [loc_idx for loc_idx in password_locations if loc_idx not in current_original_indices]; other_occurrences = len(other_indices)
                        if other_occurrences > 0:
                            print(f"  {colorize(STRINGS['warn_reused_pwd'][LANG].format(count=other_occurrences), COLOR_RED + COLOR_BOLD)}")
                            show_jump_option = True; displayed_others = 0
                            for jump_num, loc_idx in enumerate(other_indices, 1):
                                if displayed_others < 5:
                                    other_entry = all_entries_original[loc_idx]; other_host = normalize_host_from_url(other_entry.get('url','')); other_user = other_entry.get('username','')
                                    print(colorize(STRINGS['warn_reused_pwd_entry'][LANG].format(num=jump_num, orig_idx=loc_idx+1, user=other_user, host=other_host), COLOR_MAGENTA)); jump_map[jump_num] = loc_idx; displayed_others += 1
                                else: break
                            if other_occurrences > displayed_others: print(f"    {colorize(STRINGS['warn_reused_pwd_other'][LANG].format(count=other_occurrences - displayed_others), COLOR_DIM)}")
                    continue # Ask action again for current entry
                elif show_jump_option and user_input.startswith('j'):
                    if not jump_map: print(colorize(STRINGS['jump_err_no_target'][LANG], COLOR_RED)); continue
                    while True: # Inner loop for jump choice
                        try:
                            jump_choice_str = input(STRINGS['jump_prompt_select'][LANG].format(count=len(jump_map))).strip(); jump_choice = int(jump_choice_str)
                            if jump_choice == 0: print(colorize(STRINGS['jump_cancelled'][LANG], COLOR_YELLOW)); break # Break inner jump choice loop
                            if jump_choice in jump_map:
                                target_original_index = jump_map[jump_choice]; target_unique_index = -1; target_entry_original = all_entries_original[target_original_index]
                                # Find the corresponding entry in the unique list (important!)
                                for u_idx, u_entry in enumerate(unique_entries_being_processed):
                                    # Need a reliable way to map original entry to unique entry if possible
                                    # Use key fields, assuming they weren't modified *before* this jump
                                    if u_entry.get('url') == target_entry_original.get('url') and \
                                       u_entry.get('username') == target_entry_original.get('username') and \
                                       u_entry.get('password') == target_entry_original.get('password') and \
                                       u_entry.get('name') == target_entry_original.get('name') and \
                                       not u_entry.get('_to_delete'): # Make sure it's not deleted in unique list
                                        target_unique_index = u_idx
                                        break
                                if target_unique_index != -1:
                                    jump_modified = edit_specific_entry(target_unique_index, unique_entries_being_processed, changed_password_entries_for_report, manually_deleted_entries_info, all_entries_original, passwords_map)
                                    # After editing the jumped-to entry, we break the inner jump choice loop
                                    break
                                else: print(colorize(STRINGS['jump_no_unique_target'][LANG].format(index=target_original_index+1), COLOR_RED)); break # Break inner jump choice loop
                            else: print(colorize(STRINGS['jump_err_invalid_choice'][LANG], COLOR_RED))
                        except ValueError: print(colorize(STRINGS['search_err_invalid_num'][LANG], COLOR_RED)) # Reuse search string
                    # After attempting jump (or cancelling), reprint current entry info and ask action again
                    print(f"\n{colorize(STRINGS['return_to_review'][LANG].format(current=index + 1, total=total_unique_entries), COLOR_BLUE)}")
                    entry_to_process = unique_entries_being_processed[index]; current_password = entry_to_process.get('password', '') # Reload
                    print(f"{STRINGS['label_name'][LANG]}: {entry_to_process.get('name', 'N/A')}") # Reprint details
                    url_value = entry_to_process.get('url', 'N/A'); clickable_url_str = url_value
                    if url_value != 'N/A' and url_value.strip(): clickable_url_str = f"\x1b]8;;{url_value}\x1b\\{url_value}\x1b]8;;\x1b\\"
                    print(f"{STRINGS['label_url'][LANG]}: {clickable_url_str}")
                    print(f"{STRINGS['label_username'][LANG]}: {colorize(entry_to_process.get('username', 'N/A'), COLOR_YELLOW)}")
                    print(f"{STRINGS['label_password'][LANG]}: {colorize(current_password, COLOR_RED)}")
                    # Recalculate and reprint jump options
                    show_jump_option = False; jump_map = {}
                    if current_password and current_password in passwords_map:
                         password_locations = passwords_map[current_password]
                         current_original_indices = [idx_orig for idx_orig, entry in enumerate(all_entries_original) if entry.get('url') == entry_to_process.get('url') and entry.get('username') == entry_to_process.get('username') and entry.get('password') == entry_to_process.get('password') and entry.get('name') == entry_to_process.get('name')]
                         other_indices = [loc_idx for loc_idx in password_locations if loc_idx not in current_original_indices]; other_occurrences = len(other_indices)
                         if other_occurrences > 0:
                            print(f"  {colorize(STRINGS['warn_reused_pwd'][LANG].format(count=other_occurrences), COLOR_RED + COLOR_BOLD)}")
                            show_jump_option = True; displayed_others = 0
                            for jump_num, loc_idx in enumerate(other_indices, 1):
                                if displayed_others < 5:
                                     other_entry = all_entries_original[loc_idx]; other_host = normalize_host_from_url(other_entry.get('url','')); other_user = other_entry.get('username','')
                                     print(colorize(STRINGS['warn_reused_pwd_entry'][LANG].format(num=jump_num, orig_idx=loc_idx+1, user=other_user, host=other_host), COLOR_MAGENTA)); jump_map[jump_num] = loc_idx; displayed_others += 1
                                else: break
                            if other_occurrences > displayed_others: print(f"    {colorize(STRINGS['warn_reused_pwd_other'][LANG].format(count=other_occurrences - displayed_others), COLOR_DIM)}")
                    continue # Ask action G/K/D etc again for original entry

                elif user_input.startswith('g'): action = 'generate'; break
                elif user_input.startswith('k'): action = 'keep'; break
                elif user_input.startswith('d'): action = 'delete'; break
                elif user_input.startswith('o'):
                    # (Logica O invariata)
                    if url_value != 'N/A' and url_value.strip():
                        try: print(f"  {colorize(STRINGS['action_open_attempt'][LANG].format(url=url_value), COLOR_BLUE)}"); webbrowser.open(url_value); entries_opened_count += 1
                        except Exception as wb_err: print(f"  {colorize(STRINGS['action_open_err'][LANG].format(error=wb_err), COLOR_RED)}")
                    else: print(f"  {colorize(STRINGS['action_open_invalid'][LANG], COLOR_YELLOW)}")
                    continue
                elif show_view_option_v and user_input.startswith('v'):
                    # (Logica V invariata)
                    entries_viewed_count += 1; print(f"\n  {colorize(f'--- Voci Correlate Trovate per HOST: {current_host_key} ---', COLOR_MAGENTA + COLOR_BOLD)}") # Use appropriate key
                    for i, related_entry in enumerate(related_entries):
                        is_current = (related_entry == entry_to_process); is_duplicate_removed = False
                        for removed_entry in removed_duplicates_info:
                            if (related_entry.get('url','').strip() == removed_entry.get('url','').strip() and related_entry.get('username','').strip().lower() == removed_entry.get('username','').strip().lower() and related_entry.get('password','') == removed_entry.get('password','') and related_entry != entry_to_process): is_duplicate_removed = True; break
                        marker = colorize(">>> ", COLOR_YELLOW) if is_current else "    "; dup_marker = colorize("[DUPLICATO URL/User RIMOSSO]", COLOR_DIM) if is_duplicate_removed else ""
                        rel_url = related_entry.get('url', 'N/A'); rel_user = related_entry.get('username', 'N/A'); rel_pass = related_entry.get('password', 'N/A')
                        print(f"  {marker}Voce {i+1}: URL={rel_url}, User={colorize(rel_user, COLOR_YELLOW)}, Password={colorize(rel_pass, COLOR_RED)} {dup_marker}")
                    print(f"  {colorize('---------------------------------------------------------', COLOR_MAGENTA + COLOR_BOLD)}"); continue
                else: print(colorize(STRINGS['err_invalid_response'][LANG], COLOR_YELLOW))
            # --- Fine Loop While Azione ---

            # --- Esecuzione Azione ---
            if action == 'keep_all':
                 print(f"\n{colorize(STRINGS['action_bulk_ka'][LANG], COLOR_YELLOW + COLOR_BOLD)}")
                 print(STRINGS['action_bulk_ka_confirm'][LANG].format(start=index + 1, end=total_unique_entries))
                 completed_successfully = True
                 break # Esce dal for loop principale
            elif action == 'delete_all':
                 print(f"\n{colorize(STRINGS['action_bulk_da'][LANG], COLOR_RED + COLOR_BOLD)}")
                 yes_char = 'y' if LANG == 'en' else 's'
                 no_char = 'n'
                 confirm_q = STRINGS['action_bulk_da_confirm_q'][LANG].format(count=total_unique_entries - index, yes=yes_char, no=no_char)
                 delete_all_confirm = input(confirm_q).lower().strip()
                 if delete_all_confirm.startswith(yes_char):
                     print(colorize(STRINGS['action_bulk_da_exec'][LANG], COLOR_RED))
                     deleted_in_bulk = 0
                     # Usa entry_to_process che è il riferimento alla voce corrente nella lista
                     if not entry_to_process.get('_to_delete'):
                         old_pwd = entry_to_process.get('password','')
                         entry_to_process['_to_delete'] = True
                         manually_deleted_entries_info.append({'name': entry_to_process.get('name', 'N/A'), 'url': entry_to_process.get('url', 'N/A'), 'username': entry_to_process.get('username', 'N/A'), 'delete_method': 'da'})
                         update_password_map(passwords_map, all_entries_original, entry_to_process, old_pwd, None)
                         deleted_in_bulk += 1
                     for i in range(index + 1, total_unique_entries):
                         entry_ref = unique_entries_being_processed[i] # Usa riferimento diretto
                         if not entry_ref.get('_to_delete'):
                             old_pwd = entry_ref.get('password','')
                             entry_ref['_to_delete'] = True
                             manually_deleted_entries_info.append({'name': entry_ref.get('name', 'N/A'), 'url': entry_ref.get('url', 'N/A'), 'username': entry_ref.get('username', 'N/A'), 'delete_method': 'da'})
                             update_password_map(passwords_map, all_entries_original, entry_ref, old_pwd, None)
                             deleted_in_bulk += 1
                     print(colorize(STRINGS['action_bulk_da_done'][LANG].format(count=deleted_in_bulk), COLOR_RED))
                     completed_successfully = True
                     break # Esce dal for loop principale
                 else:
                     print(colorize(STRINGS['action_bulk_cancel'][LANG], COLOR_YELLOW))
                     # Se l'azione DA è annullata, non fare nulla e lascia che il for loop continui alla prossima iterazione
                     # (o se c'era un'altra azione valida scelta prima del break, quella verrà eseguita sotto)

            elif action == 'generate':
                 print(f"  {STRINGS['action_gen_start'][LANG]}...") # Già stampato prima del loop
                 entries_generated_count += 1
                 new_password = generate_strong_password()
                 old_password_g = entry_to_process.get('password','')
                 entry_to_process['password'] = new_password
                 changed_password_entries_for_report.append({'name': entry_to_process.get('name', 'N/A'), 'url': entry_to_process.get('url', 'N/A'), 'username': entry_to_process.get('username', 'N/A'), 'new_password': new_password, 'applied_to_similar': False, 'via_search': False, 'via_jump': False })
                 print(f"  {colorize(STRINGS['action_gen_done'][LANG], COLOR_GREEN)}")
                 print(f"  {colorize(STRINGS['action_gen_show_pwd'][LANG].format(password=new_password), COLOR_GREEN)}")
                 update_password_map(passwords_map, all_entries_original, entry_to_process, old_password_g, new_password)
                 current_username_lower = entry_to_process.get('username', '').strip().lower()
                 if current_host_key and current_username_lower:
                     similar_entry_indices = []
                     for other_index in range(index + 1, total_unique_entries):
                         other_entry = unique_entries_being_processed[other_index]; other_host = normalize_host_from_url(other_entry.get('url', '')); other_user_lower = other_entry.get('username', '').strip().lower()
                         if (not other_entry.get('_to_delete') and not other_entry.get('_processed_by_action') and other_host == current_host_key and other_user_lower == current_username_lower): similar_entry_indices.append(other_index)
                     if similar_entry_indices:
                         print(f"\n  {colorize(STRINGS['info_found_similar'][LANG].format(count=len(similar_entry_indices)), COLOR_YELLOW)}") # Use YELLOW
                         for idx in similar_entry_indices:
                             similar_entry_data = unique_entries_being_processed[idx]; sim_url = similar_entry_data.get('url', 'N/A'); sim_user = similar_entry_data.get('username', 'N/A'); sim_pwd = similar_entry_data.get('password', 'N/A')
                             print(f"    - Indice {idx + 1}: URL={sim_url}, User={colorize(sim_user, COLOR_YELLOW)}, Password Attuale={colorize(sim_pwd, COLOR_RED)}")
                         while True:
                             similar_prompt = STRINGS['prompt_similar_action'][LANG].format(count=len(similar_entry_indices))
                             apply_choice = input(similar_prompt).lower().strip()
                             if apply_choice.startswith('a'):
                                 print(f"  {colorize(STRINGS['action_similar_apply_ok'][LANG], COLOR_GREEN)}"); applied_count = 0
                                 for idx in similar_entry_indices:
                                      similar_entry = unique_entries_being_processed[idx]; old_sim_pwd = similar_entry.get('password','')
                                      similar_entry['password'] = new_password; similar_entry['_processed_by_action'] = True
                                      changed_password_entries_for_report.append({'name': similar_entry.get('name', 'N/A'), 'url': similar_entry.get('url', 'N/A'), 'username': similar_entry.get('username', 'N/A'), 'new_password': new_password, 'applied_to_similar': True, 'via_search': False, 'via_jump': False }); applied_count += 1
                                      update_password_map(passwords_map, all_entries_original, similar_entry, old_sim_pwd, new_password)
                                 print(f"  {colorize(STRINGS['action_similar_apply_done'][LANG].format(count=applied_count), COLOR_GREEN)}"); break
                             elif apply_choice.startswith('k'):
                                 print(f"  {colorize(STRINGS['action_similar_keep_ok'][LANG], COLOR_YELLOW)}"); kept_count_sim = 0
                                 for idx in similar_entry_indices: unique_entries_being_processed[idx]['_processed_by_action'] = True; kept_count_sim += 1
                                 print(f"  {colorize(STRINGS['action_similar_keep_done'][LANG].format(count=kept_count_sim), COLOR_YELLOW)}"); break
                             elif apply_choice.startswith('d'):
                                 print(f"  {colorize(STRINGS['action_similar_del_ok'][LANG], COLOR_RED)}"); deleted_count_sim = 0
                                 for idx in similar_entry_indices:
                                     similar_entry = unique_entries_being_processed[idx]
                                     if not similar_entry.get('_to_delete'):
                                          old_sim_pwd = similar_entry.get('password',''); similar_entry['_to_delete'] = True; similar_entry['_processed_by_action'] = True
                                          manually_deleted_entries_info.append({'name': similar_entry.get('name', 'N/A'), 'url': similar_entry.get('url', 'N/A'), 'username': similar_entry.get('username', 'N/A'), 'delete_method': 'ds'}); deleted_count_sim += 1
                                          update_password_map(passwords_map, all_entries_original, similar_entry, old_sim_pwd, None)
                                 print(f"  {colorize(STRINGS['action_similar_del_done'][LANG].format(count=deleted_count_sim), COLOR_RED)}"); break
                             elif apply_choice.startswith('n'): print(f"  {colorize(STRINGS['action_similar_none_ok'][LANG], COLOR_DIM)}"); break
                             else: print(colorize(STRINGS['err_invalid_similar_action'][LANG], COLOR_YELLOW))

            elif action == 'keep': # <<< Riga problematica originale
                 entries_kept_count += 1
                 print(f"  {colorize(STRINGS['action_keep_done'][LANG], COLOR_YELLOW)}")
            elif action == 'delete':
                 entries_deleted_count += 1
                 old_password_d = entry_to_process.get('password','')
                 entry_to_process['_to_delete'] = True
                 manually_deleted_entries_info.append({'name': entry_to_process.get('name', 'N/A'), 'url': entry_to_process.get('url', 'N/A'), 'username': entry_to_process.get('username', 'N/A'), 'delete_method': 'd'})
                 print(f"  {colorize(STRINGS['action_del_done'][LANG], COLOR_RED)}")
                 update_password_map(passwords_map, all_entries_original, entry_to_process, old_password_d, None)

            # Questo print deve essere fuori dall'if/elif delle azioni G/K/D ma dentro il for loop
            print(colorize("-------------------------------------", COLOR_DIM))

            # Salvataggio stato periodico (allineato con if/elif sopra)
            if entries_processed_this_session > 0 and entries_processed_this_session % SAVE_INTERVAL == 0 and index < total_unique_entries - 1:
                 current_state = {'unique_entries_being_processed': unique_entries_being_processed, 'all_entries_original': all_entries_original, 'original_fieldnames': original_fieldnames, 'last_processed_index': index, 'changed_password_entries_for_report': changed_password_entries_for_report, 'manually_deleted_entries_info': manually_deleted_entries_info, 'removed_duplicates_info': removed_duplicates_info}
                 save_state(current_state, STATE_FILENAME)
                 # Use a key for this message too
                 print(f"{colorize(STRINGS.get('state_saved_auto', {'it':'    (Stato salvato automaticamente dopo voce {index})','en':'    (State saved automatically after entry {index})'})[LANG].format(index=index + 1), COLOR_DIM)}")

        # --- Fine Loop For Principale ---

        if not completed_successfully: print(f"\n{colorize(STRINGS['review_end_manual'][LANG], COLOR_BLUE)}"); completed_successfully = True
        print(STRINGS['review_end_summary'][LANG].format(count=entries_processed_this_session));
        if entries_skipped_auto > 0: print(STRINGS['review_end_skipped'][LANG].format(count=entries_skipped_auto))
        print(STRINGS['review_end_recap'][LANG].format(g_count=entries_generated_count, k_count=entries_kept_count, d_count=entries_deleted_count, o_count=entries_opened_count, v_count=entries_viewed_count))

    except KeyboardInterrupt:
        print(colorize(f"\n\n{STRINGS['err_interrupt'][LANG]}", COLOR_YELLOW))
        if current_index >= 0: current_state = {'unique_entries_being_processed': unique_entries_being_processed, 'all_entries_original': all_entries_original, 'original_fieldnames': original_fieldnames, 'last_processed_index': current_index, 'changed_password_entries_for_report': changed_password_entries_for_report, 'manually_deleted_entries_info': manually_deleted_entries_info, 'removed_duplicates_info': removed_duplicates_info}; save_state(current_state, STATE_FILENAME); print(colorize(STRINGS['err_interrupt_state_saved'][LANG].format(index=current_index + 1), COLOR_YELLOW))
        else: print(colorize(STRINGS['err_interrupt_no_state'][LANG], COLOR_YELLOW))
        return

    finally:
        if completed_successfully:
            print(f"\n{STRINGS['ops_final'][LANG]}...")
            write_password_changes_report(changed_password_entries_for_report, PASSWORD_CHANGES_REPORT_FILENAME, csv_filepath)
            write_manually_deleted_report(manually_deleted_entries_info, MANUALLY_DELETED_REPORT_FILENAME, csv_filepath)
            print(f"\n{colorize(STRINGS['ops_filtering_deleted'][LANG], COLOR_CYAN)}")
            final_entries_for_csv = [entry for entry in unique_entries_being_processed if not entry.get('_to_delete', False)]
            print(STRINGS['ops_remaining_final'][LANG].format(count=len(final_entries_for_csv)))
            write_final_output_csv(final_entries_for_csv, FINAL_CSV_FILENAME, original_fieldnames)
            try:
                if os.path.exists(STATE_FILENAME): os.remove(STATE_FILENAME); print(f"\n{colorize(STRINGS['ops_state_deleted'][LANG].format(filename=STATE_FILENAME), COLOR_GREEN)}")
            except Exception as e: print(f"{colorize(STRINGS['err_state_delete'][LANG].format(filename=STATE_FILENAME, error=e), COLOR_RED)}"); print(colorize(STRINGS['warn_state_delete'][LANG], COLOR_YELLOW))


# --- Esecuzione dello script ---
if __name__ == "__main__":
    # --- SELEZIONE LINGUA ---
    while True:
        lang_choice = input(STRINGS["choose_lang"]).strip()
        if lang_choice == '1': LANG = 'it'; break
        elif lang_choice == '2': LANG = 'en'; break
        else: print(STRINGS["invalid_lang"])
    # --- FINE SELEZIONE LINGUA ---

    csv_file_path = 'passwords.csv' # MODIFICA

    # --- Stampa Intestazione ---
    print("*"*80); print(colorize(STRINGS['startup_title'][LANG], COLOR_BOLD + COLOR_CYAN)); print("*"*80)
    print(colorize(STRINGS['security_warning_header'][LANG] + " " + STRINGS['security_warning_show_pwd'][LANG], COLOR_YELLOW))
    print(colorize(STRINGS['feature_list_header'][LANG], COLOR_CYAN))
    print(f"  {STRINGS['feature_dedup'][LANG]}")
    print(f"  {STRINGS['feature_actions'][LANG]}")
    print(f"  {STRINGS['feature_bulk'][LANG]}")
    print(f"  {STRINGS['feature_other'][LANG]}")
    print(f"\n{STRINGS['file_info'][LANG].format(csv_path=csv_file_path, state_filename=STATE_FILENAME)}")
    print(colorize(STRINGS['reports_header'][LANG], COLOR_CYAN))
    print(STRINGS['report_dedup_file'][LANG].format(filename=DUPLICATE_ENTRIES_REPORT_FILENAME))
    print(STRINGS['report_gen_file'][LANG].format(filename=PASSWORD_CHANGES_REPORT_FILENAME))
    print(STRINGS['report_del_file'][LANG].format(filename=MANUALLY_DELETED_REPORT_FILENAME))
    print(colorize(STRINGS['output_header'][LANG], COLOR_CYAN))
    print(STRINGS['output_csv_file'][LANG].format(filename=FINAL_CSV_FILENAME))
    print(colorize("-----------------------------------------------------------------------------", COLOR_DIM))
    # --- Fine Intestazione ---

    abs_csv_path = os.path.abspath(csv_file_path)
    if not os.path.exists(abs_csv_path):
         print(colorize(STRINGS['err_critical_csv_not_found'][LANG].format(path=abs_csv_path), COLOR_RED))
         print(colorize(STRINGS['err_check_path'][LANG], COLOR_YELLOW))
         sys.exit(1)
    else:
        process_password_file(abs_csv_path)

    # --- Stampe Finali ---
    print(f"\n{colorize('-----------------------------------------------------------------------------', COLOR_DIM)}")
    print(colorize(STRINGS['script_terminated'][LANG], COLOR_BOLD + COLOR_BLUE))
    if os.path.exists(STATE_FILENAME):
        print(colorize(STRINGS['warn_state_exists_end'][LANG].format(filename=STATE_FILENAME), COLOR_RED + COLOR_BOLD))
        print(colorize(STRINGS['warn_state_exists_end_reason'][LANG], COLOR_YELLOW))
        print(colorize(STRINGS['warn_state_exists_end_cmd'][LANG].format(filename=STATE_FILENAME), COLOR_YELLOW))
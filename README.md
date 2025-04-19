# Chrome Exported Password Analyzer (Python)

A Python script designed to assist in reviewing, cleaning, and managing passwords exported from Google Chrome in CSV format. It helps identify reused passwords, generate strong new ones, handle duplicate or similar entries interactively, and prepare a cleaned CSV file for potential re-import (after manual password updates on websites).

> **🚨 VERY IMPORTANT SECURITY WARNING 🚨**
>
> This script **displays ALL your passwords in plain text** directly in the terminal during the review process.
> **NEVER run this script in an insecure or public environment.** Ensure no one can see your screen (shoulder surfing).
> The script includes features like search and jump which might display multiple passwords at once.
> You run this script entirely **at your own risk**. Proceed with extreme caution!

## Key Features

* **Initial Duplicate Removal:** Automatically identifies and reports entries with the exact same URL and Username, keeping only the first occurrence for review.
* **Sequential Manual Review:** Iterates through the unique entries one by one.
* **Reused Password Warning:** Automatically detects and warns if the password for the current entry is used in other entries.
* **Interactive Actions per Entry:**
    * **[G]enerate:** Creates a new, strong, random password for the current entry.
        * **Apply to Similar Option:** After generating, prompts to optionally **[A]pply** the same new password, **[K]eep** existing passwords, or **[D]elete** other unprocessed entries with the same Host and Username. Choose **[N]o Action** to handle them later.
    * **[K]eep:** Keeps the current password for the entry.
    * **[D]elete:** Marks the current entry for removal from the final output.
    * **[O]pen URL:** Attempts to open the entry's URL in the default web browser.
    * **[V]iew related:** Displays all original entries (including duplicates) associated with the same HOST (e.g., `https://example.com`).
    * **[F]ind:** Pauses sequential review to search for entries by name, URL, or username. Allows acting (G/K/D/O) on found entries within a search loop before returning to the main review sequence.
    * **[J]ump:** If a reused password warning is shown, allows jumping directly to one of the other listed entries using the same password to take action (G/K/D/O), then returns to the original entry.
* **Bulk Actions:**
    * **[KA] Keep All:** Skips the review for all remaining entries, keeping their current state.
    * **[DA] Delete All:** Marks all remaining entries for deletion (requires confirmation).
* **Multilingual UI:** Supports **Italian (it)** and **English (en)**, selectable at startup.
* **Strong Password Generation:** Creates passwords meeting complexity requirements (lowercase, uppercase, digit, punctuation).
* **State Saving/Resuming:** Automatically saves progress to a `.json` file, allowing interruption (Ctrl+C) and resuming later.
* **Reporting:** Generates `.txt` reports detailing:
    * Exact duplicates removed initially.
    * Entries whose passwords were generated (directly or applied to similar/via find/jump).
    * Entries manually marked for deletion (individually or via bulk/similar/find/jump actions).
* **Clean CSV Output:** Produces a final CSV file (`passwords_final_for_import.csv`) containing only the entries kept or updated, ready for potential re-import into Chrome or other password managers.
* **Optional Backup:** Prompts to create a timestamped backup of the original CSV file before starting.

## Requirements

* Python 3.6+
* No external libraries are needed (uses only standard Python modules).

## How to Use

1.  **Install Python 3:** If you don't have it installed, download it from [python.org](https://www.python.org/).
2.  **Download Script:** Save the script code as a Python file (e.g., `password_analyzer.py`).
3.  **Export Chrome Passwords:** Export your passwords from Chrome to a CSV file (e.g., `passwords.csv`). *Handle this file securely!*
4.  **Configure CSV Path:** **Crucially, open the script file** (`password_analyzer.py`) in a text editor and modify the line `csv_file_path = 'passwords.csv'` to point to the correct path and filename of YOUR exported CSV file.
5.  **Run from Terminal:** Open a terminal or command prompt (like Git Bash, PowerShell, or cmd on Windows) in the directory where you saved the script. Execute it using:
    ```bash
    python password_analyzer.py
    ```
6.  **Choose Language:** Select your preferred language (Italian or English) when prompted.
7.  **Backup Option:** Decide whether to create a backup of your original CSV file when asked (recommended).
8.  **Follow Prompts:** The script will guide you through the review process:
    * It will display details for each unique entry (Name, URL, Username, Current Password).
    * It will warn you if a password is reused.
    * It will prompt you for an action using the bracketed letters (e.g., `[G]`, `[K]`, `[D]`, `[F]`, etc.). Type the corresponding letter and press Enter.
    * Follow any sub-prompts (like confirming bulk delete or choosing actions for similar entries).
9.  **Interrupt / Resume:** You can safely stop the script at any time by pressing `Ctrl+C`. Your progress (including any changes made) will be saved in the `.json` state file. Simply rerun the script later to resume where you left off.
10. **Final Output:** When the review is complete (or terminated via `[KA]` / `[DA]`), the script will generate the `.txt` report files and the final `passwords_final_for_import.csv` file in the same directory.

## Generated Reports

* `duplicate_entries_removed_report.txt`: Lists entries that were identical (URL/Username) to a previous one and were automatically discarded before the manual review.
* `password_changes_report.txt`: Lists all entries for which a new password was generated (either directly via `[G]` or applied via `[A]` to similar, or via `[F]` search or `[J]` jump). **Use this report to manually update passwords on the actual websites.**
* `manually_deleted_entries_report.txt`: Lists all entries you marked for deletion using `[D]`, `[DA]`, or the delete options for similar/found/jumped entries.

## State File

* `password_review_state.json`: This file stores the current list of entries being processed (including your changes like generated passwords or delete flags) and the index of the last entry you reviewed. This allows you to resume the process. It is automatically deleted upon successful completion. It should *not* be committed to Git if you use version control (it's included in the suggested `.gitignore`).

## ❗❗ CRITICAL FINAL WARNINGS ❗❗

1.  **MANUALLY UPDATE PASSWORDS:** If you generate new passwords using this script (action `[G]` or `[A]`), you **MUST log in to each corresponding website and manually change your password to the new one generated by the script** *before* you import the final CSV file back into Chrome or any password manager. Failure to do this will lock you out or cause password mismatches. Use the `password_changes_report.txt` as your checklist.
2.  **SECURITY:** Treat your exported CSV file, the generated reports, and the final output CSV as highly sensitive data. Secure them appropriately and delete them securely when no longer needed. Running this script displays passwords on screen - ensure privacy.
3.  **BULK ACTIONS:** The `[DA]` (Delete All Remaining) and the `[D]`elete options within the "Apply to Similar" / Search / Jump features permanently mark entries for removal from the output CSV. Use these with extreme caution and double-check if unsure.

## Language Support

The script interface supports:

* Italian (`it`)
* English (`en`)

Language is selected at script startup.

## Contributing

(Optional: Add guidelines if you want others to contribute)
> Contributions, issues, and feature requests are welcome. Please open an issue first to discuss what you would like to change.

## License

(Optional: Choose and add a license)
> This project is licensed under the MIT License. See the LICENSE file for details.

*(Remember to create a `LICENSE` file in your project folder if you include this section. You can find the standard MIT License text online.)*
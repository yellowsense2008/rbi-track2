import pdfplumber
import pandas as pd
import os
from difflib import SequenceMatcher

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NBFC_CSV_PATH = os.path.join(BASE_DIR, "data", "nbfc_list.csv")
NBFC_PDF_PATH = os.path.join(BASE_DIR, "data", "nbfc_list.pdf")
ARC_FILE_PATH = os.path.join(BASE_DIR, "data", "ARC_list.csv")
ARC_NAMES = []

# Module-level DataFrame cache — read once at startup, not on every request
_nbfc_df_cache = None

def _get_nbfc_df():
    global _nbfc_df_cache
    if _nbfc_df_cache is None:
        try:
            _nbfc_df_cache = pd.read_csv(NBFC_CSV_PATH)
            print(f"[*] NBFC registry loaded: {len(_nbfc_df_cache)} entities cached in memory.")
        except FileNotFoundError:
            print("[!] WARNING: nbfc_list.csv not found. Run parse_nbfc_pdf() first.")
            _nbfc_df_cache = pd.DataFrame(columns=["company_name", "cin"])
    return _nbfc_df_cache

if os.path.exists(ARC_FILE_PATH):
    try:
        arc_df = pd.read_csv(ARC_FILE_PATH)
        arc_df.columns = arc_df.columns.astype(str).str.strip().str.lower()
        target_col = None
        for col in arc_df.columns:
            if 'name' in col or 'nbfc' in col or 'company' in col or 'entity' in col:
                target_col = col
                break
        if not target_col and len(arc_df.columns) > 1:
            target_col = arc_df.columns[1]
        elif not target_col:
            target_col = arc_df.columns[0]
        if target_col:
            ARC_NAMES = arc_df[target_col].dropna().astype(str).str.lower().str.strip().tolist()
            print(f"[*] Loaded {len(ARC_NAMES)} ARCs from column '{target_col}'")
    except Exception as e:
        print(f"[*] WARNING: Could not load ARCs list. {e}")


def is_arc_killswitch(developer_name: str) -> dict:
    if not developer_name or not ARC_NAMES:
        return {"is_arc": False, "matched_name": None}
    clean_dev_name = developer_name.lower().strip()
    for arc in ARC_NAMES:
        if clean_dev_name in arc or arc in clean_dev_name:
            return {"is_arc": True, "matched_name": arc.title()}
    return {"is_arc": False, "matched_name": None}


def parse_nbfc_pdf():
    rows = []
    with pdfplumber.open(NBFC_PDF_PATH) as pdf:
        for page in pdf.pages[2:321]:
            table = page.extract_table()
            if not table:
                continue
            for row in table[1:]:
                if row and len(row) >= 6 and row[1]:
                    rows.append({
                        "sl_no": str(row[0]).strip() if row[0] else "",
                        "company_name": str(row[1]).strip().replace("\n", " "),
                        "regional_office": str(row[2]).strip() if row[2] else "",
                        "classification": str(row[4]).strip() if row[4] else "",
                        "cin": str(row[5]).strip() if row[5] else "",
                        "address": str(row[7]).strip().replace("\n", " ") if row[7] else "",
                        "email": str(row[8]).strip() if row[8] else "",
                    })
    df = pd.DataFrame(rows)
    df.to_csv(NBFC_CSV_PATH, index=False)
    print(f"Saved {len(df)} NBFCs to {NBFC_CSV_PATH}")
    global _nbfc_df_cache
    _nbfc_df_cache = None
    return df


def lookup_nbfc(company_name: str, threshold: float = 0.82) -> dict:
    df = _get_nbfc_df()
    if df.empty or not company_name:
        return {"found": False, "score": 0, "matched_name": None, "cin": None}

    name_lower = company_name.lower().strip()

    exact = df[df['company_name'].str.lower() == name_lower]
    if not exact.empty:
        row = exact.iloc[0]
        return {"found": True, "score": 1.0, "matched_name": row["company_name"], "cin": row["cin"]}

    substr = df[df['company_name'].str.lower().str.contains(name_lower, na=False)]
    if not substr.empty:
        row = substr.iloc[0]
        return {"found": True, "score": 0.95, "matched_name": row["company_name"], "cin": row["cin"]}

    best_match = None
    best_score = 0
    for _, row in df.iterrows():
        score = SequenceMatcher(None, name_lower, str(row["company_name"]).lower()).ratio()
        if score > best_score:
            best_score = score
            best_match = row

    return {
        "found": best_score >= threshold,
        "score": round(best_score, 3),
        "matched_name": best_match["company_name"] if best_match is not None else None,
        "cin": best_match["cin"] if best_match is not None else None,
    }


if __name__ == "__main__":
    parse_nbfc_pdf()
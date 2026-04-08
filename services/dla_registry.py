import pandas as pd

DLA_EXCEL_PATH = "data/Digital Lending App.xlsx"
DLA_CSV_PATH = "data/dla_list.csv"

def parse_dla_excel():
    df = pd.read_excel(DLA_EXCEL_PATH, header=3)
    df.columns = ['blank', 'sl_no', 'entity_name', 'website', 'entity_type',
                  'dla_name', 'dla_owner', 'available_on', 'link',
                  'grievance_officer', 'grievance_email', 'grievance_phone', 'grievance_mobile']
    df = df[df['entity_name'].notna() & (df['entity_name'] != 'Entity Name')]
    df['app_id'] = df['link'].str.strip().str.extract(r'id=([a-zA-Z0-9_.]+)')
    df['entity_name'] = df['entity_name'].str.strip()
    df['dla_name'] = df['dla_name'].str.strip()
    df.to_csv(DLA_CSV_PATH, index=False)
    print(f"Saved {len(df)} DLAs to {DLA_CSV_PATH}")
    print(f"With Play Store IDs: {df['app_id'].notna().sum()}")
    return df

def lookup_dla_by_app_id(app_id: str) -> dict:
    try:
        df = pd.read_csv(DLA_CSV_PATH)
    except FileNotFoundError:
        return {"found": False, "entity_name": None, "dla_name": None}

    if not app_id:
        return {"found": False, "entity_name": None, "dla_name": None}

    match = df[df['app_id'] == app_id]
    if not match.empty:
        row = match.iloc[0]
        return {
            "found": True,
            "entity_name": row['entity_name'],
            "dla_name": row['dla_name'],
            "entity_type": row['entity_type']
        }
    return {"found": False, "entity_name": None, "dla_name": None}

def lookup_dla_by_name(dla_name: str) -> dict:
    try:
        df = pd.read_csv(DLA_CSV_PATH)
    except FileNotFoundError:
        return {"found": False, "entity_name": None}

    if not dla_name:
        return {"found": False, "entity_name": None}

    name_lower = dla_name.lower().strip()
    match = df[df['dla_name'].str.lower().str.contains(name_lower, na=False)]
    if not match.empty:
        row = match.iloc[0]
        return {"found": True, "entity_name": row['entity_name'], "dla_name": row['dla_name']}
    return {"found": False, "entity_name": None, "dla_name": None}

if __name__ == "__main__":
    parse_dla_excel()

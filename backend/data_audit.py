import pandas as pd
from urllib.parse import urlparse


def get_domain(url):
    try:
        return urlparse(str(url)).hostname or ""
    except:
        return ""


def run_audit():
    print("Loading dataset...")
    df = pd.read_csv("data/dataset_with_all_features v2.csv")

    print("\n-- Basic Statistics --")
    print(f"Total rows:    {len(df)}")
    print(f"Total columns: {len(df.columns)}")

    print("\n-- Class Distribution (All Classes) --")
    print(df['type'].value_counts())
    print(f"\nLabel column distribution:\n{df['label'].value_counts()}")

    print("\n-- Binary Filter (Benign + Phishing Only) --")
    df_binary = df[df['type'].isin(['benign', 'phishing'])].copy()
    print(f"Rows after filter: {len(df_binary)}")
    print(df_binary['type'].value_counts())
    ratio = df_binary['type'].value_counts(normalize=True) * 100
    print(f"\nClass ratio:\n{ratio.round(2)}")

    print("\n-- Duplicate Analysis --")
    total_dupes = df['url'].duplicated().sum()
    binary_dupes = df_binary['url'].duplicated().sum()
    print(f"Duplicate URLs (full dataset):   {total_dupes}")
    print(f"Duplicate URLs (binary subset):  {binary_dupes}")

    print("\n-- Missing Value Analysis --")
    missing = df.isnull().sum()
    missing_cols = missing[missing > 0]
    if len(missing_cols) == 0:
        print("No missing values found.")
    else:
        print(missing_cols)

    print("\n-- Domain Overlap Analysis --")
    df_binary['domain'] = df_binary['url'].apply(get_domain)

    benign_domains = set(
        df_binary[df_binary['type'] == 'benign']['domain']
    )
    phishing_domains = set(
        df_binary[df_binary['type'] == 'phishing']['domain']
    )
    overlap = benign_domains.intersection(phishing_domains)

    print(f"Unique domains (benign):   {len(benign_domains)}")
    print(f"Unique domains (phishing): {len(phishing_domains)}")
    print(f"Overlapping domains:       {len(overlap)}")
    print(f"Overlap rate:              {len(overlap)/len(benign_domains)*100:.2f}%")

    if len(overlap) > 0:
        print("\nSample overlapping domains (first 10):")
        for d in list(overlap)[:10]:
            print(f"  {d}")

    print("\n-- Collection Period --")
    if 'Date_inspection' in df.columns:
        df['Date_inspection'] = pd.to_datetime(
            df['Date_inspection'], errors='coerce'
        )
        print(f"Earliest date: {df['Date_inspection'].min()}")
        print(f"Latest date:   {df['Date_inspection'].max()}")
        print(f"Date range:    {(df['Date_inspection'].max() - df['Date_inspection'].min()).days} days")
    else:
        print("No date column found.")

    print("\n-- Saving Cleaned Dataset --")
    df_clean = df_binary.drop_duplicates(subset=['url']).copy()
    df_clean = df_clean.drop(columns=['domain'])
    df_clean.to_csv("data/dataset_clean.csv", index=False)
    print(f"Cleaned dataset saved: {len(df_clean)} rows")
    print("Path: data/dataset_clean.csv")

    print("\n-- Audit Complete --")


if __name__ == "__main__":
    run_audit()